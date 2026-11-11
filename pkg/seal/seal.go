// Package seal turns a Trustee config tree into a Sealed Bundle and back.
// A Sealed Bundle is a tar of the tree, encrypted with age to the bootstrap
// recipient, exactly as `tar -C dir -cf - . | age -r <recipient>` makes it.
package seal

import (
	"archive/tar"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"filippo.io/age"
)

// Seal writes the Sealed Bundle of dir to dst, encrypted to recipient. It
// fails once the bundle grows past MaxSize, which the Bootstrap Helper would
// refuse to read.
func Seal(dst io.Writer, dir, recipient string) error {
	r, err := age.ParseX25519Recipient(recipient)
	if err != nil {
		return fmt.Errorf("parse recipient: %w", err)
	}
	enc, err := age.Encrypt(&capped{w: dst}, r)
	if err != nil {
		return fmt.Errorf("start encryption: %w", err)
	}
	tw := tar.NewWriter(enc)
	if err := tw.AddFS(os.DirFS(dir)); err != nil {
		return fmt.Errorf("tar %s: %w", dir, err)
	}
	if err := tw.Close(); err != nil {
		return fmt.Errorf("close tar: %w", err)
	}
	if err := enc.Close(); err != nil {
		return fmt.Errorf("finish encryption: %w", err)
	}
	return nil
}

// MaxSize caps the Sealed Bundle and the file contents it unseals to
// (1 MiB): the bundle travels in a ConfigMap. age doesn't compress, but a
// sparse tar entry can unpack larger than its bytes in the bundle.
const MaxSize = 1048576

// errTooLarge is a Sealed Bundle over the size cap.
var errTooLarge = errors.New("the Sealed Bundle is over the 1 MiB size cap")

// capped writes to w until the total would pass MaxSize, then fails.
type capped struct {
	w io.Writer
	n int
}

func (c *capped) Write(p []byte) (int, error) {
	c.n += len(p)
	if c.n > MaxSize {
		return 0, errTooLarge
	}
	return c.w.Write(p)
}

// Unseal decrypts bundle with id and extracts it into the new directory dst.
// It refuses absolute paths, "..", any entry but a directory or a regular
// file (so symlinks, hardlinks and device files), and file contents over
// MaxSize in total. os.Root keeps every entry inside dst.
func Unseal(bundle []byte, id age.Identity, dst string) error {
	plain, err := age.Decrypt(bytes.NewReader(bundle), id)
	if err != nil {
		return fmt.Errorf("decrypt bundle: %w", err)
	}
	if err := os.Mkdir(dst, 0o700); err != nil {
		return fmt.Errorf("create %s: %w", dst, err)
	}
	root, err := os.OpenRoot(dst)
	if err != nil {
		return fmt.Errorf("open %s: %w", dst, err)
	}
	defer root.Close()
	tr := tar.NewReader(plain)
	var size int64
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("read bundle: %w", err)
		}
		if hdr.Size > MaxSize-size {
			return fmt.Errorf("%s: the bundle unseals to over %d bytes", hdr.Name, MaxSize)
		}
		size += hdr.Size
		if err := extract(root, hdr, tr); err != nil {
			return err
		}
	}
}

func extract(root *os.Root, hdr *tar.Header, r io.Reader) error {
	if !filepath.IsLocal(hdr.Name) || slices.Contains(strings.Split(hdr.Name, "/"), "..") {
		return fmt.Errorf("%s: path is absolute or holds ..", hdr.Name)
	}
	switch hdr.Typeflag {
	case tar.TypeDir:
		if err := root.MkdirAll(hdr.Name, 0o700); err != nil {
			return fmt.Errorf("create %s: %w", hdr.Name, err)
		}
		return nil
	case tar.TypeReg:
		return writeFile(root, hdr.Name, r)
	default:
		return fmt.Errorf("%s: unsupported tar entry type %q", hdr.Name, hdr.Typeflag)
	}
}

func writeFile(root *os.Root, name string, r io.Reader) error {
	f, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("create %s: %w", name, err)
	}
	if _, err := io.Copy(f, r); err != nil {
		return errors.Join(fmt.Errorf("write %s: %w", name, err), f.Close())
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close %s: %w", name, err)
	}
	return nil
}
