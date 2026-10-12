package broker

import "testing"

func TestFilterSkipsFlagged(t *testing.T) {
	db := &BrokerDatabase{Brokers: []Broker{
		{ID: "live", Name: "Live", Email: "privacy@live.example", Region: "us"},
		{ID: "dead", Name: "Dead", Email: "privacy@dead.example", Region: "us", Tags: []string{"flagged", "dead-email"}},
		{ID: "review", Name: "Review", Email: "privacy@review.example", Region: "us", Tags: []string{"needs-review"}},
	}}

	got := db.Filter(nil, nil)
	if len(got) != 2 {
		t.Fatalf("got %d brokers, want 2", len(got))
	}
	for _, b := range got {
		if b.ID == "dead" {
			t.Fatal("flagged broker was included")
		}
	}
}

func TestIsFlagged(t *testing.T) {
	if (Broker{Tags: []string{"Flagged"}}).IsFlagged() != true {
		t.Fatal("expected flagged tag to match regardless of case")
	}
	if (Broker{Tags: []string{"needs-review"}}).IsFlagged() {
		t.Fatal("needs-review is not a send block")
	}
}
