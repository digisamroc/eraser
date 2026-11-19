package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/eraser-privacy/eraser/internal/broker"
	"github.com/eraser-privacy/eraser/internal/config"
	"github.com/go-chi/chi/v5"
)

func TestSendOneRefusesFormOnlyBroker(t *testing.T) {
	db := &broker.BrokerDatabase{Brokers: []broker.Broker{{
		ID: "form-co", Name: "Form Co", Email: "privacy@form.example", Region: "us",
		Tags: []string{broker.TagFormOnly},
	}}}
	cfg := &config.Config{Email: config.EmailConfig{Provider: "smtp", From: "me@example.com"}}
	s, err := NewServer(0, cfg, "", db, nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/send/form-co", nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("brokerID", "form-co")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	rec := httptest.NewRecorder()

	s.handleAPISendOne(rec, req)

	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "opt-out form") {
		t.Fatalf("got %d %q, want 400 refusing form-only broker", rec.Code, rec.Body.String())
	}
}
