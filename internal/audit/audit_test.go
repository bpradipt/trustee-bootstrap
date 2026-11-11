package audit_test

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/confidential-devhub/trustee-bootstrap/internal/audit"
)

func TestErrorKeepsTheFirstLineOnly(t *testing.T) {
	var b bytes.Buffer
	audit.New(&b).Info(audit.ApproveResult, audit.Error(errors.New("start KBS: exit status 1\nkbs output")))
	if got := b.String(); !strings.Contains(got, `"error":"start KBS: exit status 1"`) || strings.Contains(got, "kbs output") {
		t.Errorf("record = %s, want only the error's first line", got)
	}
}

func TestErrorOmitsNil(t *testing.T) {
	var b bytes.Buffer
	audit.New(&b).Info(audit.ApproveResult, audit.Error(nil))
	if got := b.String(); strings.Contains(got, "error") {
		t.Errorf("record = %s, want no error key", got)
	}
}
