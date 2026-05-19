package main

import (
	"context"
	"database/sql"
	"log"
	"net/http"
	"os"
	"time"

	_ "github.com/jackc/pgx/v4/stdlib"
	"github.com/joho/godotenv"

	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/metric"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
	"go.opentelemetry.io/otel/trace"
)

type App struct {
	DB        *sql.DB
	MasterKey string
	Tracer    trace.Tracer

	AuthValidations metric.Int64Counter
	AuthErrors      metric.Int64Counter
	AuthDuration    metric.Float64Histogram
}

func initTracerProvider(ctx context.Context, serviceName string, endpoint string) (*sdktrace.TracerProvider, error) {
	traceExporter, err := otlptracehttp.New(
		ctx,
		otlptracehttp.WithEndpoint(endpoint),
		otlptracehttp.WithInsecure(),
	)
	if err != nil {
		return nil, err
	}

	res, err := resource.New(
		ctx,
		resource.WithAttributes(
			semconv.ServiceName(serviceName),
			attribute.String("service.version", getenvDefault("SERVICE_VERSION", "1.0.0")),
			attribute.String("deployment.environment", getenvDefault("ENVIRONMENT", "dev")),
		),
	)
	if err != nil {
		return nil, err
	}

	tp := sdktrace.NewTracerProvider(
		sdktrace.WithResource(res),
		sdktrace.WithBatcher(traceExporter),
	)

	otel.SetTracerProvider(tp)

	return tp, nil
}

func initMeterProvider(ctx context.Context, serviceName string, endpoint string) (*sdkmetric.MeterProvider, error) {
	metricExporter, err := otlpmetrichttp.New(
		ctx,
		otlpmetrichttp.WithEndpoint(endpoint),
		otlpmetrichttp.WithInsecure(),
	)
	if err != nil {
		return nil, err
	}

	res, err := resource.New(
		ctx,
		resource.WithAttributes(
			semconv.ServiceName(serviceName),
			attribute.String("service.version", getenvDefault("SERVICE_VERSION", "1.0.0")),
			attribute.String("deployment.environment", getenvDefault("ENVIRONMENT", "dev")),
		),
	)
	if err != nil {
		return nil, err
	}

	mp := sdkmetric.NewMeterProvider(
		sdkmetric.WithResource(res),
		sdkmetric.WithReader(
			sdkmetric.NewPeriodicReader(
				metricExporter,
				sdkmetric.WithInterval(10*time.Second),
			),
		),
	)

	otel.SetMeterProvider(mp)

	return mp, nil
}

func main() {
	_ = godotenv.Load()

	port := getenvDefault("PORT", "8001")

	databaseURL := os.Getenv("DATABASE_URL")
	if databaseURL == "" {
		log.Fatal("DATABASE_URL deve ser definida")
	}

	masterKey := os.Getenv("MASTER_KEY")
	if masterKey == "" {
		log.Fatal("MASTER_KEY deve ser definida")
	}

	serviceName := getenvDefault("OTEL_SERVICE_NAME", "auth-service")
	otelEndpoint := getenvDefault(
		"OTEL_EXPORTER_OTLP_ENDPOINT",
		"otel-collector.monitoring.svc.cluster.local:4318",
	)

	ctx := context.Background()

	tracerProvider, err := initTracerProvider(ctx, serviceName, otelEndpoint)
	if err != nil {
		log.Fatalf("Erro ao inicializar tracer provider: %v", err)
	}
	defer func() {
		if err := tracerProvider.Shutdown(ctx); err != nil {
			log.Printf("Erro ao finalizar tracer provider: %v", err)
		}
	}()

	meterProvider, err := initMeterProvider(ctx, serviceName, otelEndpoint)
	if err != nil {
		log.Fatalf("Erro ao inicializar meter provider: %v", err)
	}
	defer func() {
		if err := meterProvider.Shutdown(ctx); err != nil {
			log.Printf("Erro ao finalizar meter provider: %v", err)
		}
	}()

	tracer := otel.Tracer("auth-service")
	meter := otel.Meter("auth-service")

	authValidations, err := meter.Int64Counter(
		"auth_validations_total",
		metric.WithDescription("Total de validações de chave feitas pelo auth-service"),
		metric.WithUnit("1"),
	)
	if err != nil {
		log.Fatalf("Erro ao criar métrica auth_validations_total: %v", err)
	}

	authErrors, err := meter.Int64Counter(
		"auth_errors_total",
		metric.WithDescription("Total de erros no auth-service"),
		metric.WithUnit("1"),
	)
	if err != nil {
		log.Fatalf("Erro ao criar métrica auth_errors_total: %v", err)
	}

	authDuration, err := meter.Float64Histogram(
		"auth_validation_duration_seconds",
		metric.WithDescription("Duração das validações de chave"),
		metric.WithUnit("s"),
	)
	if err != nil {
		log.Fatalf("Erro ao criar métrica auth_validation_duration_seconds: %v", err)
	}

	db, err := connectDB(databaseURL)
	if err != nil {
		log.Fatalf("Não foi possível conectar ao banco de dados: %v", err)
	}
	defer db.Close()

	app := &App{
		DB:              db,
		MasterKey:       masterKey,
		Tracer:          tracer,
		AuthValidations: authValidations,
		AuthErrors:      authErrors,
		AuthDuration:    authDuration,
	}

	mux := http.NewServeMux()

	mux.Handle(
		"/health",
		otelhttp.NewHandler(http.HandlerFunc(app.healthHandler), "GET /health"),
	)

	mux.Handle(
		"/validate",
		otelhttp.NewHandler(http.HandlerFunc(app.validateKeyHandler), "GET /validate"),
	)

	mux.Handle(
		"/admin/keys",
		otelhttp.NewHandler(
			app.masterKeyAuthMiddleware(http.HandlerFunc(app.createKeyHandler)),
			"POST /admin/keys",
		),
	)

	log.Printf("Serviço de Autenticação (Go) rodando na porta %s", port)

	if err := http.ListenAndServe(":"+port, mux); err != nil {
		log.Fatal(err)
	}
}

func connectDB(databaseURL string) (*sql.DB, error) {
	db, err := sql.Open("pgx", databaseURL)
	if err != nil {
		return nil, err
	}

	if err = db.Ping(); err != nil {
		return nil, err
	}

	log.Println("Conectado ao PostgreSQL com sucesso!")
	return db, nil
}

func getenvDefault(key string, fallback string) string {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}
	return value
}
