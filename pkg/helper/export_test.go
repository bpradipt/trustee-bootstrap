package helper

import "testing"

// SetRename puts f in place of os.Rename at publication's commit point until
// the test ends, so a test can crash the helper just before or just after it.
func SetRename(t *testing.T, f func(oldpath, newpath string) error) {
	t.Helper()
	old := rename
	rename = f
	t.Cleanup(func() { rename = old })
}
