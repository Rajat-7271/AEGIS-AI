package normalizer

import (
	"encoding/json"
	"testing"
)

// Synthetic metadata only: no claim of detection or downstream deduplication.
func TestWindowsBridgeFullIdentitySurvivesNormalization(t *testing.T) {
	n := newLenientNormalizer()
	identity := []interface{}{"synthetic-device", "Security", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "synthetic-host", 1}
	normalize := func(parts []interface{}, tenant string) *NormalizedEvent {
		t.Helper()
		encoded, err := json.Marshal(parts)
		if err != nil {
			t.Fatal(err)
		}
		external := "windows-v2:" + string(encoded)
		event, err := n.Normalize(&RawEvent{
			ConnectorID:   "11111111-1111-4111-8111-111111111111",
			ConnectorType: "windows_event", SourceFormat: "raw_json", TenantID: tenant,
			ReceivedAt: "2026-11-13T00:00:00Z",
			Payload: map[string]interface{}{
				"source": "windows_event", "external_id": external,
				"title": "Synthetic Windows Security EventID 1102", "severity": "info",
				"hostname": parts[3], "created_at": "2026-11-13T00:00:00Z",
				"raw_event": map[string]interface{}{"EventID": 1102, "Channel": "Security", "synthetic": true, "receipt_identity": parts},
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		if got := nested(t, event.OcsfEvent, "finding.uid"); got != external {
			t.Fatalf("finding.uid = %v, want %s", got, external)
		}
		return event
	}
	tenant := "22222222-2222-4222-8222-222222222222"
	first := normalize(identity, tenant)
	if replay := normalize(identity, tenant); replay.ID != first.ID {
		t.Fatal("identical retry changed event ID")
	}
	for i, replacement := range []interface{}{"other-device", "other-channel", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "other-host", 2} {
		parts := append([]interface{}{}, identity...)
		parts[i] = replacement
		if changed := normalize(parts, tenant); changed.ID == first.ID {
			t.Fatalf("identity dimension %d collided", i)
		}
	}
	if changed := normalize(identity, "33333333-3333-4333-8333-333333333333"); changed.ID == first.ID {
		t.Fatal("tenant IDs collided")
	}
}
