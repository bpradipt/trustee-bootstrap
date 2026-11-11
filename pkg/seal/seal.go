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
	"io/fs"
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
			return fmt.Errorf("bundle: read tar: %w", cause(err))
		}
		if hdr.Size > MaxSize-size {
			return errors.New("bundle: unseals to over the 1 MiB size cap")
		}
		size += hdr.Size
		if err := extract(root, hdr, tr); err != nil {
			return err
		}
	}
}

// extract writes one entry into root. Entry names are plaintext metadata
// (spec §0.6), so its errors give a fixed reason and never the name.
func extract(root *os.Root, hdr *tar.Header, r io.Reader) error {
	if !filepath.IsLocal(hdr.Name) || slices.Contains(strings.Split(hdr.Name, "/"), "..") {
		return errors.New("bundle: entry path is absolute or holds ..")
	}
	switch hdr.Typeflag {
	case tar.TypeDir:
		if err := root.MkdirAll(hdr.Name, 0o700); err != nil {
			return fmt.Errorf("bundle: create a directory entry: %w", cause(err))
		}
		return nil
	case tar.TypeReg:
		return writeFile(root, hdr.Name, r)
	default:
		return errors.New("bundle: entry type not allowed")
	}
}

func writeFile(root *os.Root, name string, r io.Reader) error {
	f, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("bundle: create a file entry: %w", cause(err))
	}
	if _, err := io.Copy(f, r); err != nil {
		return errors.Join(fmt.Errorf("bundle: write a file entry: %w", cause(err)), cause(f.Close()))
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("bundle: close a file entry: %w", cause(err))
	}
	return nil
}

// cause is err without the path that an *fs.PathError carries.
func cause(err error) error {
	var pe *fs.PathError
	if errors.As(err, &pe) {
		return pe.Err
	}
	return err
}
