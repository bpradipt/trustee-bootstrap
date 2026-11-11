// Package verifier runs the Operator Verifier: the pinned Trustee KBS with
// its built-in AS, listening on 127.0.0.1, with the default secure Operator
// Verifier config and the Share payload as its only resource.
package verifier

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/BurntSushi/toml"
)

// Image is the digest-pinned Trustee KBS image with the built-in AS
// (docs/upstream-pins.md).
const Image = "ghcr.io/confidential-containers/key-broker-service:built-in-as-v0.22.0@sha256:c1960cb4df0b1bdc0e4309f97dc65b0a1a777a92dabb2211acb45542f906c625"

// ShareResource is the KBS resource that holds the Share payload.
const ShareResource = "trustee-bootstrap/share/current"

// Where the container sees the run directory, and the port KBS listens on
// inside it.
const (
	containerRoot = "/etc/kbs"
	containerPort = "8080"
)

// asPolicyDir is where KBS's built-in AS stores its policies (LocalFs
// namespace attestation_service_policy).
const asPolicyDir = "storage/attestation_service_policy"

// Options is one Operator Verifier run.
type Options struct {
	// KBSBinary runs a natively installed kbs instead of Image.
	KBSBinary       string
	ResourcePolicy  string              // Rego
	ReferenceValues map[string][]string // loaded into the built-in RVPS
	SharePayload    []byte
}

// Runtime is how the Operator Verifier reaches the operator's machine.
type Runtime struct {
	Engine string // podman or docker, for Image
	// Listen picks the port: the verifier briefly listens on the address
	// Start gets, then hands the port to KBS.
	Listen func(network, address string) (net.Listener, error)
	Client *http.Client // probes KBS until it answers
}

// DefaultEngine is podman when it is installed, else docker.
func DefaultEngine() string {
	if _, err := exec.LookPath("podman"); err == nil {
		return "podman"
	}
	return "docker"
}

// Start runs the Operator Verifier on address (a 127.0.0.1 address; port 0
// picks one) and returns the address it serves on once KBS answers. stop
// ends KBS and deletes its run directory.
func (r Runtime) Start(ctx context.Context, address string, opts Options) (addr string, stop func(), err error) {
	parent := runtimeDir()
	if err := checkTmpfs(parent); err != nil {
		return "", nil, err
	}
	addr, err = r.reservePort(address)
	if err != nil {
		return "", nil, err
	}
	dir, err := os.MkdirTemp(parent, "trustee-bootstrap-verifier-")
	if err != nil {
		return "", nil, fmt.Errorf("create run directory: %w", err)
	}
	end, err := r.launch(ctx, dir, addr, opts)
	if err != nil {
		os.RemoveAll(dir)
		return "", nil, err
	}
	return addr, func() { end(); os.RemoveAll(dir) }, nil
}

// reservePort picks the port, on 127.0.0.1 only (AT-02).
func (r Runtime) reservePort(address string) (string, error) {
	l, err := r.Listen("tcp", address)
	if err != nil {
		return "", fmt.Errorf("pick a port: %w", err)
	}
	addr := l.Addr().String()
	if err := l.Close(); err != nil {
		return "", fmt.Errorf("pick a port: %w", err)
	}
	if host, _, _ := net.SplitHostPort(addr); host != "127.0.0.1" {
		return "", fmt.Errorf("the Operator Verifier listens on 127.0.0.1 only, not %s", addr)
	}
	return addr, nil
}

// runtimeDir is the user's tmpfs runtime directory.
func runtimeDir() string {
	if d := os.Getenv("XDG_RUNTIME_DIR"); d != "" {
		return d
	}
	return "/dev/shm"
}

// tmpfsMagic is Linux's TMPFS_MAGIC (statfs(2)).
const tmpfsMagic = 0x01021994

// checkTmpfs refuses a run directory parent that is not tmpfs: the run
// directory holds the Share payload, which must never reach a disk.
func checkTmpfs(dir string) error {
	var st syscall.Statfs_t
	if err := syscall.Statfs(dir, &st); err != nil {
		return fmt.Errorf("check run directory: %w", err)
	}
	if st.Type != tmpfsMagic {
		return fmt.Errorf("%s is not on tmpfs; set XDG_RUNTIME_DIR to a tmpfs directory", dir)
	}
	return nil
}

// launch writes the run directory, starts KBS and waits until it answers.
func (r Runtime) launch(ctx context.Context, dir, addr string, opts Options) (func(), error) {
	cfg := DefaultConfig(containerRoot, net.JoinHostPort("0.0.0.0", containerPort))
	args := []string{r.Engine, "run", "--rm", "-p", addr + ":" + containerPort,
		"-v", dir + ":" + containerRoot + ":Z", Image,
		"/usr/local/bin/kbs", "--config-file", filepath.Join(containerRoot, ConfigFile)}
	if opts.KBSBinary != "" {
		cfg = DefaultConfig(dir, addr)
		args = []string{opts.KBSBinary, "--config-file", filepath.Join(dir, ConfigFile)}
	}
	if err := CheckSecure(cfg); err != nil {
		return nil, fmt.Errorf("refusing to start an insecure Operator Verifier: %w", err)
	}
	if err := writeRunDir(dir, cfg, opts); err != nil {
		return nil, err
	}
	runCtx, cancel := context.WithCancel(ctx)
	cmd := exec.CommandContext(runCtx, args[0], args[1:]...)
	// SIGTERM lets the engine stop and remove the container.
	cmd.Cancel = func() error { return cmd.Process.Signal(syscall.SIGTERM) }
	cmd.WaitDelay = time.Minute
	// KBS output stays in memory and is shown only if KBS fails to start,
	// before it has seen any evidence.
	out := &tail{n: maxKBSOutput}
	cmd.Stdout, cmd.Stderr = out, out
	if err := cmd.Start(); err != nil {
		cancel()
		return nil, fmt.Errorf("start KBS: %w", err)
	}
	exited := make(chan struct{})
	go func() { cmd.Wait(); close(exited) }()
	end := func() { cancel(); <-exited }
	if err := r.waitReady(ctx, addr, exited); err != nil {
		end()
		return nil, fmt.Errorf("start KBS: %w\n%s", err, strings.TrimSpace(string(out.b)))
	}
	return end, nil
}

// maxKBSOutput bounds the KBS output kept in memory (64 KiB).
const maxKBSOutput = 65536

// tail keeps the last n bytes written to it.
type tail struct {
	b []byte
	n int
}

func (t *tail) Write(p []byte) (int, error) {
	t.b = append(t.b, p...)
	t.b = t.b[max(len(t.b)-t.n, 0):]
	return len(p), nil
}

// waitReady polls KBS until it answers any HTTP request.
func (r Runtime) waitReady(ctx context.Context, addr string, exited <-chan struct{}) error {
	for !r.answers(ctx, "http://"+addr+"/") {
		select {
		case <-exited:
			return errors.New("KBS exited")
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Second):
		}
	}
	return nil
}

func (r Runtime) answers(ctx context.Context, url string) bool {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return false
	}
	resp, err := r.Client.Do(req)
	if err != nil {
		return false
	}
	resp.Body.Close()
	return true
}

// writeRunDir writes the KBS config, the per-run keys and the KBS storage:
// the resource policy, the reference values and the Share payload.
func writeRunDir(dir string, cfg Config, opts Options) error {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return fmt.Errorf("open run directory: %w", err)
	}
	defer root.Close()
	files, err := runFiles(cfg, opts)
	if err != nil {
		return err
	}
	// KBS writes the AS's default policies here. Creating the directory
	// first keeps it the operator's, so stop can delete the files a rootful
	// engine writes into it as root.
	if err := root.MkdirAll(asPolicyDir, 0o700); err != nil {
		return fmt.Errorf("create %s: %w", asPolicyDir, err)
	}
	for name, data := range files {
		if err := root.MkdirAll(filepath.Dir(name), 0o700); err != nil {
			return fmt.Errorf("create %s: %w", filepath.Dir(name), err)
		}
		if err := root.WriteFile(name, data, 0o600); err != nil {
			return fmt.Errorf("write %s: %w", name, err)
		}
	}
	return nil
}

// runFiles returns the run directory's files by path.
func runFiles(cfg Config, opts Options) (map[string][]byte, error) {
	adminPub, err := adminPublicKey()
	if err != nil {
		return nil, err
	}
	key, cert, err := tokenSigner()
	if err != nil {
		return nil, err
	}
	var config bytes.Buffer
	if err := toml.NewEncoder(&config).Encode(cfg); err != nil {
		return nil, fmt.Errorf("encode KBS config: %w", err)
	}
	// KBS LocalFs storage: <namespace>/<key>, with '/' in a key as \x2F.
	files := map[string][]byte{
		ConfigFile:         config.Bytes(),
		AdminPublicKeyFile: adminPub,
		SignerKeyFile:      key,
		SignerCertFile:     cert,
		ResourcePolicyPath: []byte(opts.ResourcePolicy),
		filepath.Join(StorageDir, "repository", strings.ReplaceAll(ShareResource, "/", `\x2F`)): opts.SharePayload,
	}
	for name, values := range opts.ReferenceValues {
		rv, err := referenceValue(name, values)
		if err != nil {
			return nil, err
		}
		files[filepath.Join(StorageDir, "reference_value", name)] = rv
	}
	return files, nil
}

// adminPublicKey returns the PEM public half of a fresh admin key. The
// private half is dropped, so nobody can call the admin API.
func adminPublicKey() ([]byte, error) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate admin key: %w", err)
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, fmt.Errorf("encode admin key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), nil
}

// tokenSigner returns a fresh P-256 AS token signing key and its
// self-signed certificate, both PEM.
func tokenSigner() (key, cert []byte, err error) {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate AS signer: %w", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(k)
	if err != nil {
		return nil, nil, fmt.Errorf("encode AS signer: %w", err)
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "trustee-bootstrap Operator Verifier AS signer"},
		NotBefore:             now,
		NotAfter:              now.AddDate(0, 0, 1),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		return nil, nil, fmt.Errorf("certify AS signer: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}), nil
}

// referenceValue is the built-in RVPS's stored form of a sample reference
// value (Trustee v0.22.0 rvps/src/reference_value.rs).
func referenceValue(name string, values []string) ([]byte, error) {
	b, err := json.Marshal(map[string]any{
		"version":    "0.1.0",
		"name":       name,
		"expiration": time.Now().UTC().AddDate(1, 0, 0).Format("2006-01-02T15:04:05Z"),
		"value":      values,
	})
	if err != nil {
		return nil, fmt.Errorf("encode reference value %s: %w", name, err)
	}
	return b, nil
}
