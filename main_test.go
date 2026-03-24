package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHealthHandler(t *testing.T) {
	app := &App{}

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rr := httptest.NewRecorder()

	handler := http.HandlerFunc(app.healthHandler)
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status esperado %d, obtido %d", http.StatusOK, rr.Code)
	}

	var body map[string]string
	err := json.Unmarshal(rr.Body.Bytes(), &body)
	if err != nil {
		t.Fatalf("erro ao decodificar JSON: %v", err)
	}

	if body["status"] != "ok" {
		t.Fatalf("status esperado 'ok', obtido '%s'", body["status"])
	}
}
