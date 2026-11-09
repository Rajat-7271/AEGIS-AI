package publisher

import (
    "context"
    "math"
    "strings"
    "testing"

    "github.com/beenuar/aisoc/services/ingest/internal/normalizer"
)

// Serialization must fail before touching the Kafka writer. A nil writer
// deliberately makes an accidental write attempt fail this test immediately.
func TestPublishBatchRejectsUnserializableEventWithoutWriting(t *testing.T) {
    p := &Publisher{}
    events := []*normalizer.NormalizedEvent{
        {ID: "valid", TenantID: "tenant", OcsfEvent: map[string]interface{}{"message": "ok"}},
        {ID: "bad", TenantID: "tenant", OcsfEvent: map[string]interface{}{"score": math.NaN()}},
    }
    err := p.PublishBatch(context.Background(), events)
    if err == nil {
        t.Fatal("expected serialization failure, got success acknowledgement")
    }
    if !strings.Contains(err.Error(), "failed to marshal event bad") {
        t.Fatalf("unexpected error: %v", err)
    }
}
