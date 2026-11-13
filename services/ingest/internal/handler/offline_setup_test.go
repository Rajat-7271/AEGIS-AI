package handler

import (
	"encoding/json"
	"os"
	"testing"
)

// Authorization tests must reach the real normalizer without CDN access.
func TestAuthSetupHasLocalATTCKBundle(t *testing.T) {
	raw, err := os.ReadFile(testConfig().AttckDataPath)
	if err != nil {
		t.Fatal(err)
	}
	var bundle struct {
		Objects []json.RawMessage `json:"objects"`
	}
	if err := json.Unmarshal(raw, &bundle); err != nil || bundle.Objects == nil {
		t.Fatalf("invalid synthetic STIX bundle: %s", raw)
	}
}
