package main

import (
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

// Estrutura para o corpo da requisição de criação de chave
type CreateKeyRequest struct {
	Name string `json:"name"`
}

// Estrutura para a resposta da criação de chave
type CreateKeyResponse struct {
	Name    string `json:"name"`
	Key     string `json:"key"`
	Message string `json:"message"`
}

func (a *App) healthHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func (a *App) validateKeyHandler(w http.ResponseWriter, r *http.Request) {
	start := time.Now()

	ctx, span := a.Tracer.Start(r.Context(), "validate_api_key")
	defer span.End()

	authHeader := r.Header.Get("Authorization")
	keyString := strings.TrimPrefix(authHeader, "Bearer ")

	if keyString == "" {
		a.AuthErrors.Add(ctx, 1,
			metric.WithAttributes(
				attribute.String("operation", "validate"),
				attribute.String("error_type", "missing_authorization_header"),
			),
		)

		a.AuthValidations.Add(ctx, 1,
			metric.WithAttributes(attribute.String("status", "missing_header")),
		)

		a.AuthDuration.Record(ctx, time.Since(start).Seconds(),
			metric.WithAttributes(attribute.String("status", "missing_header")),
		)

		http.Error(w, "Authorization header não encontrado", http.StatusUnauthorized)
		return
	}

	keyHash := hashAPIKey(keyString)

	var id int
	err := a.DB.QueryRow(
		"SELECT id FROM api_keys WHERE key_hash = $1 AND is_active = true",
		keyHash,
	).Scan(&id)

	if err != nil {
		log.Printf("Falha na validação da chave (hash: %s...): %v", keyHash[:6], err)

		a.AuthErrors.Add(ctx, 1,
			metric.WithAttributes(
				attribute.String("operation", "validate"),
				attribute.String("error_type", "invalid_or_inactive_key"),
			),
		)

		a.AuthValidations.Add(ctx, 1,
			metric.WithAttributes(attribute.String("status", "invalid")),
		)

		a.AuthDuration.Record(ctx, time.Since(start).Seconds(),
			metric.WithAttributes(attribute.String("status", "invalid")),
		)

		span.RecordError(err)
		span.SetAttributes(
			attribute.String("auth.validation.status", "invalid"),
		)

		http.Error(w, "Chave de API inválida ou inativa", http.StatusUnauthorized)
		return
	}

	a.AuthValidations.Add(ctx, 1,
		metric.WithAttributes(attribute.String("status", "success")),
	)

	a.AuthDuration.Record(ctx, time.Since(start).Seconds(),
		metric.WithAttributes(attribute.String("status", "success")),
	)

	span.SetAttributes(
		attribute.String("auth.validation.status", "success"),
		attribute.Int("auth.api_key.id", id),
	)

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "Chave válida"})
}

func (a *App) createKeyHandler(w http.ResponseWriter, r *http.Request) {
	start := time.Now()

	ctx, span := a.Tracer.Start(r.Context(), "create_api_key")
	defer span.End()

	if r.Method != http.MethodPost {
		a.AuthErrors.Add(ctx, 1,
			metric.WithAttributes(
				attribute.String("operation", "create_key"),
				attribute.String("error_type", "method_not_allowed"),
			),
		)

		http.Error(w, "Método não permitido", http.StatusMethodNotAllowed)
		return
	}

	var req CreateKeyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		a.AuthErrors.Add(ctx, 1,
			metric.WithAttributes(
				attribute.String("operation", "create_key"),
				attribute.String("error_type", "invalid_body"),
			),
		)

		span.RecordError(err)
		http.Error(w, "Corpo da requisição inválido", http.StatusBadRequest)
		return
	}

	if req.Name == "" {
		a.AuthErrors.Add(ctx, 1,
			metric.WithAttributes(
				attribute.String("operation", "create_key"),
				attribute.String("error_type", "missing_name"),
			),
		)

		http.Error(w, "O campo 'name' é obrigatório", http.StatusBadRequest)
		return
	}

	span.SetAttributes(attribute.String("auth.key.name", req.Name))

	newKey, err := generateAPIKey()
	if err != nil {
		a.AuthErrors.Add(ctx, 1,
			metric.WithAttributes(
				attribute.String("operation", "create_key"),
				attribute.String("error_type", "key_generation_error"),
			),
		)

		span.RecordError(err)
		http.Error(w, "Erro ao gerar a chave", http.StatusInternalServerError)
		return
	}

	newKeyHash := hashAPIKey(newKey)

	var newID int
	err = a.DB.QueryRow(
		"INSERT INTO api_keys (name, key_hash) VALUES ($1, $2) RETURNING id",
		req.Name, newKeyHash,
	).Scan(&newID)

	if err != nil {
		log.Printf("Erro ao salvar a chave no banco: %v", err)

		a.AuthErrors.Add(ctx, 1,
			metric.WithAttributes(
				attribute.String("operation", "create_key"),
				attribute.String("error_type", "database_error"),
			),
		)

		span.RecordError(err)
		http.Error(w, "Erro ao salvar a chave", http.StatusInternalServerError)
		return
	}

	a.AuthValidations.Add(ctx, 1,
		metric.WithAttributes(attribute.String("status", "key_created")),
	)

	a.AuthDuration.Record(ctx, time.Since(start).Seconds(),
		metric.WithAttributes(attribute.String("status", "key_created")),
	)

	span.SetAttributes(
		attribute.String("auth.operation", "create_key"),
		attribute.Int("auth.api_key.id", newID),
	)

	log.Printf("Nova chave criada com sucesso (ID: %d, Name: %s)", newID, req.Name)

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(CreateKeyResponse{
		Name:    req.Name,
		Key:     newKey,
		Message: "Guarde esta chave com segurança! Você não poderá vê-la novamente.",
	})
}

func (a *App) masterKeyAuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		ctx, span := a.Tracer.Start(r.Context(), "validate_master_key")
		defer span.End()

		authHeader := r.Header.Get("Authorization")
		keyString := strings.TrimPrefix(authHeader, "Bearer ")

		if keyString != a.MasterKey {
			a.AuthErrors.Add(ctx, 1,
				metric.WithAttributes(
					attribute.String("operation", "master_key_auth"),
					attribute.String("error_type", "unauthorized"),
				),
			)

			a.AuthValidations.Add(ctx, 1,
				metric.WithAttributes(attribute.String("status", "master_key_invalid")),
			)

			a.AuthDuration.Record(ctx, time.Since(start).Seconds(),
				metric.WithAttributes(attribute.String("status", "master_key_invalid")),
			)

			http.Error(w, "Acesso não autorizado", http.StatusForbidden)
			return
		}

		a.AuthValidations.Add(ctx, 1,
			metric.WithAttributes(attribute.String("status", "master_key_success")),
		)

		a.AuthDuration.Record(ctx, time.Since(start).Seconds(),
			metric.WithAttributes(attribute.String("status", "master_key_success")),
		)

		span.SetAttributes(attribute.String("auth.master_key.status", "success"))

		next.ServeHTTP(w, r)
	})
}
