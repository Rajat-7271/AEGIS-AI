package normalizer

import "testing"

// The Windows shipper emits canonical envelopes, not raw WEF records.
// Ensure the Go ingest path preserves tenant, host, severity and replay identity.
func TestWindowsShipperEnvelopeNormalizesAndReplays(t *testing.T) {
	n := newTestNormalizer()
	payload := map[string]interface{}{
		"source": "windows_event",
		"category": "edr",
		"severity": "high",
		"title": "Windows Security EventID 1102",
		"external_id": "winrec:v1:6:host-18:security3:901",
		"hostname": "host-1",
		"created_at": "2026-11-10T10:00:00Z",
		"raw_event": map[string]interface{}{
			"System": map[string]interface{}{"EventID": 1102, "Channel": "Security", "Computer": "host-1"},
			"EventData": map[string]interface{}{},
		},
	}
	raw := &RawEvent{
		ConnectorID: "22222222-2222-4222-8222-222222222222",
		ConnectorType: "windows_event",
		TenantID: "11111111-1111-4111-8111-111111111111",
		ReceivedAt: "2026-11-10T10:00:05Z",
		Payload: payload,
	}
	first, err := n.Normalize(raw)
	if err != nil { t.Fatalf("first normalize: %v", err) }
	raw.ReceivedAt = "2026-11-10T11:00:05Z"
	second, err := n.Normalize(raw)
	if err != nil { t.Fatalf("replay normalize: %v", err) }
	if first.ID == "" || first.ID != second.ID {
		t.Fatalf("replay ID changed: %q vs %q", first.ID, second.ID)
	}
	if first.TenantID != raw.TenantID { t.Fatalf("wrong tenant: %s", first.TenantID) }
	if first.OcsfEvent["event_id"] != first.ID { t.Fatal("OCSF event ID differs from envelope ID") }
	if first.OcsfEvent["category_uid"] != 1 { t.Fatalf("Windows telemetry should be category 1: %v", first.OcsfEvent["category_uid"]) }
	if first.OcsfEvent["severity_id"] != 4 { t.Fatalf("Windows log clear must be high severity: %v", first.OcsfEvent["severity_id"]) }
	if first.OcsfEvent["time"] != "2026-11-10T10:00:00Z" { t.Fatalf("event time not preserved: %v", first.OcsfEvent["time"]) }
	other := *raw
	other.TenantID = "33333333-3333-4333-8333-333333333333"
	crossTenant, err := n.Normalize(&other)
	if err != nil { t.Fatal(err) }
	if crossTenant.ID == first.ID { t.Fatal("cross-tenant event ID collision") }
}
