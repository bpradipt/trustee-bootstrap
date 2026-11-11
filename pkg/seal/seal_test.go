package seal_test

import (
	"archive/tar"
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"filippo.io/age"

	"github.com/confidential-devhub/trustee-bootstrap/pkg/seal"
)

func newIdentity(t *testing.T) *age.X25519Identity {
	t.Helper()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestSealThenUnsealRestoresTree(t *testing.T) {
	src := t.TempDir()
	if err := os.MkdirAll(filepath.Join(src, "policy"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "kbs-config.toml"), []byte("insecure_http = false\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "policy", "resource.rego"), []byte("package policy\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	id := newIdentity(t)
	var bundle bytes.Buffer
	if err := seal.Seal(&bundle, src, id.Recipient().String()); err != nil {
		t.Fatal(err)
	}

	dst := filepath.Join(t.TempDir(), "out")
	if err := seal.Unseal(bundle.Bytes(), id, dst); err != nil {
		t.Fatal(err)
	}
	if got := readFile(t, filepath.Join(dst, "policy", "resource.rego")); got != "package policy\n" {
		t.Errorf("resource.rego = %q", got)
	}
	if got := readFile(t, filepath.Join(dst, "kbs-config.toml")); got != "insecure_http = false\n" {
		t.Errorf("kbs-config.toml = %q", got)
	}
	info, err := os.Stat(filepath.Join(dst, "kbs-config.toml"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("file mode = %v, want 0600", info.Mode().Perm())
	}
}

func TestSealRejectsBadRecipient(t *testing.T) {
	if err := seal.Seal(new(bytes.Buffer), t.TempDir(), "age1notarecipient"); err == nil {
		t.Fatal("Seal accepted a bad recipient")
	}
}

// stockBundle builds what `tar -C dir -cf - . | age -r <recipient>` produces:
// GNU tar's "./" names, then age's binary format.
func stockBundle(t *testing.T, recipient age.Recipient, entries []*tar.Header, body string) []byte {
	t.Helper()
	var bundle bytes.Buffer
	enc, err := age.Encrypt(&bundle, recipient)
	if err != nil {
		t.Fatal(err)
	}
	tw := tar.NewWriter(enc)
	for _, hdr := range entries {
		if hdr.Typeflag == tar.TypeReg {
			hdr.Size = int64(len(body))
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if hdr.Typeflag == tar.TypeReg {
			if _, err := tw.Write([]byte(body)); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := enc.Close(); err != nil {
		t.Fatal(err)
	}
	return bundle.Bytes()
}

func TestUnsealAcceptsStockAgeBundle(t *testing.T) {
	id := newIdentity(t)
	bundle := stockBundle(t, id.Recipient(), []*tar.Header{
		{Name: "./", Typeflag: tar.TypeDir, Mode: 0o755},
		{Name: "./kbs/", Typeflag: tar.TypeDir, Mode: 0o755},
		{Name: "./kbs/config.toml", Typeflag: tar.TypeReg, Mode: 0o644},
	}, "sockets = []\n")
	dst := filepath.Join(t.TempDir(), "out")
	if err := seal.Unseal(bundle, id, dst); err != nil {
		t.Fatal(err)
	}
	if got := readFile(t, filepath.Join(dst, "kbs", "config.toml")); got != "sockets = []\n" {
		t.Errorf("config.toml = %q", got)
	}
}

func TestUnsealRejectsWrongIdentity(t *testing.T) {
	bundle := stockBundle(t, newIdentity(t).Recipient(), nil, "")
	dst := filepath.Join(t.TempDir(), "out")
	if err := seal.Unseal(bundle, newIdentity(t), dst); err == nil {
		t.Fatal("Unseal accepted the wrong identity")
	}
	if _, err := os.Stat(dst); !os.IsNotExist(err) {
		t.Errorf("Unseal created %s for a bundle it could not decrypt", dst)
	}
}

// AT-14: extraction refuses a booby-trapped tar.
func TestUnsealRejectsHostileEntries(t *testing.T) {
	for name, hdr := range map[string]*tar.Header{
		"..":            {Name: "../escape", Typeflag: tar.TypeReg},
		".. inside":     {Name: "kbs/../escape", Typeflag: tar.TypeReg},
		"absolute path": {Name: "/etc/escape", Typeflag: tar.TypeReg},
		"symlink":       {Name: "link", Typeflag: tar.TypeSymlink, Linkname: "/etc/passwd"},
		"hardlink":      {Name: "link", Typeflag: tar.TypeLink, Linkname: "kbs.toml"},
		"char device":   {Name: "tty", Typeflag: tar.TypeChar, Devmajor: 5},
		"block device":  {Name: "disk", Typeflag: tar.TypeBlock, Devmajor: 8},
		"fifo":          {Name: "pipe", Typeflag: tar.TypeFifo},
	} {
		t.Run(name, func(t *testing.T) {
			id := newIdentity(t)
			bundle := stockBundle(t, id.Recipient(), []*tar.Header{
				{Name: "kbs/", Typeflag: tar.TypeDir, Mode: 0o700},
				{Name: "kbs.toml", Typeflag: tar.TypeReg, Mode: 0o600},
				hdr,
			}, "x")
			if err := seal.Unseal(bundle, id, filepath.Join(t.TempDir(), "out")); err == nil {
				t.Fatalf("Unseal accepted %+v", hdr)
			}
		})
	}
}

func TestUnsealRejectsCorruptBundle(t *testing.T) {
	id := newIdentity(t)
	bundle := stockBundle(t, id.Recipient(), []*tar.Header{{Name: "kbs.toml", Typeflag: tar.TypeReg}}, "x")
	bundle[len(bundle)-1] ^= 1
	if err := seal.Unseal(bundle, id, filepath.Join(t.TempDir(), "out")); err == nil {
		t.Fatal("Unseal accepted a corrupt bundle")
	}
}

func TestUnsealAcceptsTheSizeCap(t *testing.T) {
	id := newIdentity(t)
	bundle := stockBundle(t, id.Recipient(), []*tar.Header{{Name: "big", Typeflag: tar.TypeReg}}, string(make([]byte, seal.MaxSize)))
	if err := seal.Unseal(bundle, id, filepath.Join(t.TempDir(), "out")); err != nil {
		t.Fatal(err)
	}
}

// AT-14: files under the cap one by one, over it together.
func TestUnsealRejectsMoreThanTheSizeCap(t *testing.T) {
	id := newIdentity(t)
	bundle := stockBundle(t, id.Recipient(), []*tar.Header{
		{Name: "a", Typeflag: tar.TypeReg},
		{Name: "b", Typeflag: tar.TypeReg},
	}, string(make([]byte, seal.MaxSize/2+1)))
	if err := seal.Unseal(bundle, id, filepath.Join(t.TempDir(), "out")); err == nil {
		t.Fatal("Unseal extracted more than the size cap")
	}
}

// Seal refuses a tree whose Sealed Bundle would be over the 1 MiB size cap
// (spec §3): the helper would refuse to read it.
func TestSealRefusesABundleOverTheSizeCap(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "big"), make([]byte, seal.MaxSize), 0o600); err != nil {
		t.Fatal(err)
	}
	var b bytes.Buffer
	if err := seal.Seal(&b, dir, newIdentity(t).Recipient().String()); err == nil {
		t.Fatalf("Seal wrote a %d-byte bundle", b.Len())
	}
}

func TestCappedWriterTakesExactlyTheSizeCap(t *testing.T) {
	var b bytes.Buffer
	w := seal.CappedWriter(&b)
	if _, err := w.Write(make([]byte, seal.MaxSize)); err != nil {
		t.Fatalf("writing the size cap: %v", err)
	}
	if _, err := w.Write([]byte{0}); err == nil {
		t.Fatal("the writer took a byte past the size cap")
	}
	if b.Len() != seal.MaxSize {
		t.Errorf("wrote %d bytes, want %d", b.Len(), seal.MaxSize)
	}
}
