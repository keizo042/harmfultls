package harmtls

import (
	"testing"
)

func TestAlert(t *testing.T) {
	alert := Alert{
		Level:       Fatal,
		Description: CloseNotify,
	}

	bytes, err := alert.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	actual := new(Alert)
	if err := actual.UnmarshalBinary(bytes); err != nil {
		t.Fatal(err)
	}
	if alert.Level != actual.Level {
		t.Fatalf("expected: %d, actual: %d", alert.Level, actual.Level)
	}
	if alert.Description != actual.Description {
		t.Fatalf("expected: %d, actual: %d", alert.Description, actual.Description)
	}
}
