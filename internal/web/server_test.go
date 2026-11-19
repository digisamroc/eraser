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

func TestBrokersPageShowsConfiguredDailyLimit(t *testing.T) {
	var many []broker.Broker
	for i := range 5 {
		many = append(many, broker.Broker{ID: "b" + strings.Repeat("x", i+1), Name: "B", Email: "p@b.example", Region: "us"})
	}
	db := &broker.BrokerDatabase{Brokers: many}

	for name, cfg := range map[string]*config.Config{
		"no config yet": nil,
		"custom limit":  {Options: config.Options{DailyLimit: 3}},
	} {
		t.Run(name, func(t *testing.T) {
			s, err := NewServer(0, cfg, "", db, nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			rec := httptest.NewRecorder()
			s.handleBrokers(rec, httptest.NewRequest(http.MethodGet, "/brokers", nil))
			if rec.Code != http.StatusOK {
				t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
			}
			banner := strings.Contains(rec.Body.String(), "sends up to 3 emails per 24 hours")
			if (cfg != nil) != banner {
				t.Errorf("banner shown = %v, want %v", banner, cfg != nil)
			}
		})
	}
}

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
