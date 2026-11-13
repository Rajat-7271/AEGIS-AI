package handler

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

// Real HTTP and normalizer, with controlled credential stores and publisher.
// This does not assert Kafka delivery or duplicate-alert prevention.
func TestWindowsSyntheticHTTPIdentityAndTenantBoundary(t *testing.T) {
	h, pub := newAuthHandler(t, "")
	server := httptest.NewServer(http.HandlerFunc(h.IngestEvents))
	defer server.Close()
	body, err := json.Marshal(map[string]any{
		"connector_id":   "11111111-1111-4111-8111-111111111111",
		"connector_type": "windows_event", "source_format": "raw_json",
		"events": []map[string]any{{
			"source": "windows_event", "severity": "info",
			"external_id": `windows-v2:["synthetic-device","Security","aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","synthetic-host",1]`,
			"hostname":    "synthetic-host", "created_at": "2026-11-13T00:00:00Z",
			"raw_event": map[string]any{"EventID": 1102, "synthetic": true},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	post := func(token, tenant string, want int) {
		t.Helper()
		req, err := http.NewRequest(http.MethodPost, server.URL+"/v1/ingest/batch", bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("X-Tenant-ID", tenant)
		req.Header.Set("Content-Type", "application/json")
		response, err := server.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		data, err := io.ReadAll(response.Body)
		if err != nil || response.StatusCode != want {
			t.Fatalf("status=%d body=%s error=%v", response.StatusCode, data, err)
		}
		if want == http.StatusOK {
			var accepted IngestResponse
			if err := json.Unmarshal(data, &accepted); err != nil || accepted.Accepted != 1 || accepted.Rejected != 0 {
				t.Fatalf("unexpected acceptance: %s", data)
			}
		}
	}
	post(umbraToken, umbraTenant.String(), http.StatusOK)
	post(acmeToken, acmeTenant.String(), http.StatusOK)
	post(acmeToken, acmeTenant.String(), http.StatusOK)
	post(acmeToken, umbraTenant.String(), http.StatusForbidden)
	post("invalid", acmeTenant.String(), http.StatusUnauthorized)
	pub.mu.Lock()
	defer pub.mu.Unlock()
	if len(pub.published) != 3 {
		t.Fatalf("unauthorized publication: %d events", len(pub.published))
	}
	if pub.published[1].ID != pub.published[2].ID {
		t.Fatal("retry changed normalized identity")
	}
	if pub.published[0].ID == pub.published[1].ID {
		t.Fatal("different tenants shared normalized identity")
	}
}
