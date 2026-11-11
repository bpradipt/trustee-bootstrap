package trusteetest_test

import (
	"testing"

	"github.com/confidential-devhub/trustee-bootstrap/internal/trusteetest"
	"github.com/confidential-devhub/trustee-bootstrap/pkg/verifier"
)

func TestEachViolationBreaksTheTree(t *testing.T) {
	if err := verifier.CheckSealedConfig(trusteetest.Tree(t, "/trustee/config"), "/trustee/config"); err != nil {
		t.Fatalf("Tree fails the sealed-config checks: %v", err)
	}
	for _, v := range trusteetest.Violations {
		dir := trusteetest.Tree(t, "/trustee/config")
		v.Apply(t, dir)
		if err := verifier.CheckSealedConfig(dir, "/trustee/config"); err == nil {
			t.Errorf("%s: the tree still passes", v.Name)
		}
	}
}
