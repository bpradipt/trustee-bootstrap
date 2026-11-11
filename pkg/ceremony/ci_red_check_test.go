package ceremony

import "testing"

// TestCIRedCheck fails on purpose. It exists only on the ci-red-check
// branch, to prove that CI blocks a broken pull request. Never merge it.
func TestCIRedCheck(t *testing.T) {
	t.Fatal("deliberate failure: CI must turn this pull request red")
}
