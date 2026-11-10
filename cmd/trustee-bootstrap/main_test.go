package main

import "testing"

func TestRunExitCodes(t *testing.T) {
	if code := run([]string{"--help"}); code != 0 {
		t.Errorf("--help exited %d, want 0", code)
	}
	if code := run([]string{"no-such-command"}); code != 1 {
		t.Errorf("unknown command exited %d, want 1", code)
	}
}
