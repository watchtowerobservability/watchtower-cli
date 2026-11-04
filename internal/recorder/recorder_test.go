package recorder

import "testing"

func TestPasswordValuesNeverLeaveTheRecorder(t *testing.T) {
	e, ok := parseEvent(`{"type":"input","el":{"tag":"input","id":"pw","password":true},"value":"hunter2"}`)
	if !ok || e.Value != "" || !e.El.Password {
		t.Fatalf("password event kept its value: %+v", e)
	}
	e, ok = parseEvent(`{"type":"input","el":{"tag":"input","id":"user"},"value":"alice"}`)
	if !ok || e.Value != "alice" {
		t.Fatalf("plain input lost its value: %+v", e)
	}
	if _, ok := parseEvent(`not json`); ok {
		t.Fatal("malformed report accepted")
	}
}
