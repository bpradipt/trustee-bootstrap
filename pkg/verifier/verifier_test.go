package verifier_test

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/BurntSushi/toml"

	"github.com/confidential-devhub/trustee-bootstrap/internal/memnet"
	"github.com/confidential-devhub/trustee-bootstrap/pkg/verifier"
)

func TestDefaultConfigIsSecure(t *testing.T) {
	c := verifier.DefaultConfig("/etc/kbs", "127.0.0.1:8080")
	if err := verifier.CheckSecure(c); err != nil {
		t.Fatalf("CheckSecure(DefaultConfig) = %v", err)
	}
	if !c.HTTPServer.InsecureHTTP || c.SessionStorageType != "Memory" {
		t.Errorf("DefaultConfig = %+v, want plain HTTP and in-memory sessions", c)
	}
	if want := []string{"/etc/kbs/as-signer.crt"}; !slices.Equal(c.AttestationToken.TrustedCertsPaths, want) ||
		c.AttestationService.TokenBroker.Signer.CertPath != want[0] {
		t.Errorf("KBS trusts %v, the AS signs with %s; want both %s",
			c.AttestationToken.TrustedCertsPaths, c.AttestationService.TokenBroker.Signer.CertPath, want[0])
	}

	jwk := c
	jwk.AttestationToken.InsecureHeaderJWK = true
	open := c
	open.Admin.AuthorizationMode = "InsecureAllowAll"
	for name, tt := range map[string]struct {
		c    verifier.Config
		want []string
	}{
		"insecure_header_jwk": {jwk, []string{"insecure_header_jwk"}},
		"InsecureAllowAll":    {open, []string{"authorization_mode"}},
		"both":                {verifier.Config{}, []string{"insecure_header_jwk", "authorization_mode"}},
	} {
		if name == "both" {
			tt.c = open
			tt.c.AttestationToken.InsecureHeaderJWK = true
		}
		err := verifier.CheckSecure(tt.c)
		for _, w := range tt.want {
			if err == nil || !strings.Contains(err.Error(), w) {
				t.Errorf("%s: CheckSecure = %v, want it to name %s", name, err, w)
			}
		}
	}
}

func TestDefaultTrusteeConfig(t *testing.T) {
	c := verifier.DefaultTrusteeConfig("/trustee/config")
	if err := verifier.CheckSecure(c); err != nil {
		t.Fatalf("CheckSecure(DefaultTrusteeConfig) = %v", err)
	}
	if c.HTTPServer.InsecureHTTP || c.HTTPServer.PrivateKey != "/trustee/config/tls.key" ||
		c.HTTPServer.Certificate != "/trustee/config/tls.crt" {
		t.Errorf("http_server = %+v, want HTTPS with Trustee's sealed key", c.HTTPServer)
	}
	if c.StorageBackend.Backends.LocalFS.DirPath != "/trustee/config/storage" || c.SessionStorageType != "Memory" {
		t.Errorf("storage = %+v, sessions %q; want the published tree and in-memory sessions",
			c.StorageBackend, c.SessionStorageType)
	}

	// The example config is the default, key for key.
	var example verifier.Config
	md, err := toml.DecodeFile("../../deploy/examples/trustee-config/kbs.toml", &example)
	if err != nil {
		t.Fatal(err)
	}
	if extra := md.Undecoded(); len(extra) > 0 {
		t.Errorf("the example config sets keys the default does not: %v", extra)
	}
	if !reflect.DeepEqual(example, c) {
		t.Errorf("example config = %+v\nwant %+v", example, c)
	}
}

// answering is a KBS that answers the readiness probe once the fake
// executable has recorded its arguments.
type answering struct{ executable string }

func (a answering) RoundTrip(*http.Request) (*http.Response, error) {
	if _, err := os.Stat(a.executable + ".args"); err != nil {
		return nil, errors.New("connection refused")
	}
	return &http.Response{StatusCode: http.StatusUnauthorized, Body: http.NoBody}, nil
}

// silent is a KBS that never answers.
type silent struct{}

func (silent) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("connection refused")
}

// fakeExecutable writes a shell script that records its arguments in
// <path>.args and then runs body.
func fakeExecutable(t *testing.T, name, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	script := "#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$0.tmp\" && mv \"$0.tmp\" \"$0.args\"\n" + body + "\n"
	if err := os.WriteFile(path, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	return path
}

// fakeEngine writes a container engine. ps prints <path>.ps, and fails once
// that file is gone. rm logs its container to <path>.rm, and fails while
// <path>.rmfail exists. run records its arguments, as fakeExecutable does,
// and sleeps like KBS.
func fakeEngine(t *testing.T, ps ...string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "podman")
	script := `#!/bin/sh
case "$1" in
ps) cat "$0.ps"; exit ;;
rm) echo "$3" >>"$0.rm"; test ! -e "$0.rmfail"; exit ;;
esac
printf '%s\n' "$@" > "$0.tmp" && mv "$0.tmp" "$0.args"
exec sleep 60
`
	if err := os.WriteFile(path, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path+".ps", []byte(strings.Join(ps, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func recordedArgs(t *testing.T, executable string) []string {
	t.Helper()
	b, err := os.ReadFile(executable + ".args")
	if err != nil {
		t.Fatal(err)
	}
	return strings.Split(strings.TrimSuffix(string(b), "\n"), "\n")
}

func runtime(rt http.RoundTripper, engine string) verifier.Runtime {
	var loopback memnet.Network
	return verifier.Runtime{Engine: engine, Listen: loopback.Listen, Client: &http.Client{Transport: rt}}
}

var opts = verifier.Options{
	ResourcePolicy:  "package policy\n",
	ReferenceValues: map[string][]any{"trusted_aks": {"AK"}},
	SharePayload:    []byte(`{"index":1}`),
}

// tmpfsMagic is Linux's TMPFS_MAGIC.
const tmpfsMagic = 0x01021994

// tmpfsDir returns a fresh directory on tmpfs, where the Operator Verifier
// must keep its run directory.
func tmpfsDir(t *testing.T) string {
	t.Helper()
	for _, parent := range []string{os.Getenv("XDG_RUNTIME_DIR"), "/dev/shm", os.TempDir()} {
		var st syscall.Statfs_t
		if parent == "" || syscall.Statfs(parent, &st) != nil || st.Type != tmpfsMagic {
			continue
		}
		if dir, err := os.MkdirTemp(parent, "verifier-test-"); err == nil {
			t.Cleanup(func() {
				if err := os.RemoveAll(dir); err != nil {
					t.Error(err)
				}
			})
			return dir
		}
	}
	t.Skip("no writable tmpfs directory")
	return ""
}

func TestStartKBSBinary(t *testing.T) {
	runDirs := tmpfsDir(t)
	t.Setenv("XDG_RUNTIME_DIR", runDirs)
	kbs := fakeExecutable(t, "kbs", "exec sleep 60")
	o := opts
	o.KBSBinary = kbs

	addr, stop, err := runtime(answering{kbs}, "podman").Start(t.Context(), "127.0.0.1:0", o)
	if err != nil {
		t.Fatal(err)
	}
	if addr != "127.0.0.1:0" {
		t.Errorf("addr = %s, want the reserved 127.0.0.1 address", addr)
	}
	args := recordedArgs(t, kbs)
	dir := filepath.Dir(args[1])
	if len(args) != 2 || args[0] != "--config-file" || filepath.Dir(dir) != runDirs {
		t.Fatalf("kbs args = %q, want --config-file <run dir in XDG_RUNTIME_DIR>/kbs.toml", args)
	}
	var got verifier.Config
	if _, err := toml.DecodeFile(args[1], &got); err != nil {
		t.Fatal(err)
	}
	if want := verifier.DefaultConfig(dir, addr); !reflect.DeepEqual(got, want) {
		t.Errorf("kbs.toml = %+v\nwant %+v", got, want)
	}
	assertRunDir(t, dir)

	if err := stop(); err != nil {
		t.Errorf("stop = %v", err)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Errorf("run directory survived stop: %v", err)
	}
}

// The run directory holds the Share payload, so stop reports a wipe that
// failed rather than leave it behind silently.
func TestStopReportsAFailedWipe(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root deletes from a read-only directory")
	}
	t.Setenv("XDG_RUNTIME_DIR", tmpfsDir(t))
	kbs := fakeExecutable(t, "kbs", "exec sleep 60")
	o := opts
	o.KBSBinary = kbs
	_, stop, err := runtime(answering{kbs}, "").Start(t.Context(), "127.0.0.1:0", o)
	if err != nil {
		t.Fatal(err)
	}
	// A read-only subdirectory with a file in it: RemoveAll can't empty it.
	stuck := filepath.Join(filepath.Dir(recordedArgs(t, kbs)[1]), "stuck")
	if err := os.Mkdir(stuck, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stuck, "f"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(stuck, 0o500); err != nil {
		t.Fatal(err)
	}
	if err := stop(); err == nil || !strings.Contains(err.Error(), "Share payload") {
		t.Errorf("stop = %v, want the failed wipe reported", err)
	}
	if err := os.Chmod(stuck, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := stop(); err != nil {
		t.Errorf("stop after the fix = %v", err)
	}
}

func assertRunDir(t *testing.T, dir string) {
	t.Helper()
	read := func(name string) []byte {
		t.Helper()
		path := filepath.Join(dir, name)
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Errorf("%s mode = %v, want 0600", name, info.Mode().Perm())
		}
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	block, _ := pem.Decode(read(verifier.AdminPublicKeyFile))
	if pub, err := x509.ParsePKIXPublicKey(block.Bytes); err != nil {
		t.Errorf("admin key: %v", err)
	} else if _, ok := pub.(ed25519.PublicKey); !ok {
		t.Errorf("admin key is %T, want Ed25519", pub)
	}
	assertSigner(t, read(verifier.SignerKeyFile), read(verifier.SignerCertFile))
	storage := filepath.Join(verifier.StorageDir)
	// KBS v0.22.0 installs its built-in default policy unless this exact
	// key holds one.
	if got := string(read(filepath.Join(storage, "kbs", "resource-policy.rego"))); got != opts.ResourcePolicy {
		t.Errorf("resource policy = %q", got)
	}
	if got := string(read(filepath.Join(storage, "repository", `trustee-bootstrap\x2Fshare\x2Fcurrent`))); got != string(opts.SharePayload) {
		t.Errorf("Share payload resource = %q", got)
	}
	var rv struct {
		Version, Name, Expiration string
		Value                     []string
	}
	if err := json.Unmarshal(read(filepath.Join(storage, "reference_value", "trusted_aks")), &rv); err != nil {
		t.Fatal(err)
	}
	if rv.Version != "0.1.0" || rv.Name != "trusted_aks" || !slices.Equal(rv.Value, []string{"AK"}) || len(rv.Expiration) != 20 {
		t.Errorf("reference value = %+v", rv)
	}
	// KBS writes the AS's default policies here. A rootful engine writes
	// them as root, so the directory must already be the operator's.
	if info, err := os.Stat(filepath.Join(dir, storage, "attestation_service_policy")); err != nil || !info.IsDir() {
		t.Errorf("AS policy directory not created up front: %v", err)
	}
}

// assertSigner checks that the AS signer's certificate is self-signed for
// its key, so KBS can verify the AS's tokens against it.
func assertSigner(t *testing.T, keyPEM, certPEM []byte) {
	t.Helper()
	kb, _ := pem.Decode(keyPEM)
	key, err := x509.ParseECPrivateKey(kb.Bytes)
	if err != nil {
		t.Fatalf("AS signer key: %v", err)
	}
	cb, _ := pem.Decode(certPEM)
	cert, err := x509.ParseCertificate(cb.Bytes)
	if err != nil {
		t.Fatalf("AS signer cert: %v", err)
	}
	if !key.PublicKey.Equal(cert.PublicKey.(*ecdsa.PublicKey)) {
		t.Error("AS signer cert is not for its key")
	}
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	if _, err := cert.Verify(x509.VerifyOptions{Roots: roots}); err != nil {
		t.Errorf("AS signer cert does not verify against itself: %v", err)
	}
}

func TestStartContainer(t *testing.T) {
	t.Setenv("XDG_RUNTIME_DIR", tmpfsDir(t))
	engine := fakeEngine(t)

	addr, stop, err := runtime(answering{engine}, engine).Start(t.Context(), "127.0.0.1:0", opts)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := stop(); err != nil {
			t.Error(err)
		}
	})
	args := recordedArgs(t, engine)
	dir := strings.TrimSuffix(args[7], ":/etc/kbs:Z")
	// The container is named after its run directory, so a later run's
	// sweep can find it (ticket 20).
	want := []string{"run", "--rm", "--name", filepath.Base(dir), "-p", addr + ":8080", "-v", dir + ":/etc/kbs:Z", verifier.Image,
		"/usr/local/bin/kbs", "--config-file", "/etc/kbs/kbs.toml"}
	if !slices.Equal(args, want) {
		t.Fatalf("engine args = %q\nwant %q", args, want)
	}
	var got verifier.Config
	if _, err := toml.DecodeFile(filepath.Join(dir, verifier.ConfigFile), &got); err != nil {
		t.Fatal(err)
	}
	if want := verifier.DefaultConfig("/etc/kbs", "0.0.0.0:8080"); !reflect.DeepEqual(got, want) {
		t.Errorf("kbs.toml = %+v\nwant %+v", got, want)
	}
}

// runPrefix names each run directory and its container.
const runPrefix = "trustee-bootstrap-verifier-"

// mkRun makes a run directory in parent with a stand-in Share payload.
func mkRun(t *testing.T, parent, name string) string {
	t.Helper()
	dir := filepath.Join(parent, name)
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "share"), []byte("share"), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

// lockDir holds dir locked, as a live run does.
func lockDir(t *testing.T, dir string) {
	t.Helper()
	f, err := os.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.Close() })
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		t.Fatal(err)
	}
}

func exists(t *testing.T, path string) bool {
	t.Helper()
	_, err := os.Stat(path)
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	return err == nil
}

// Ticket 20: a run that died without stopping (SIGKILL, an OOM kill) leaves
// its run directory, with the Share payload, and maybe its container. The
// next Start removes both and says so. It leaves alone a run that a live
// process holds, a run directory not yet named, and anything not a run.
func TestStartSweepsEarlierRuns(t *testing.T) {
	runDirs := tmpfsDir(t)
	t.Setenv("XDG_RUNTIME_DIR", runDirs)
	stale := mkRun(t, runDirs, runPrefix+"stale")
	lockDir(t, mkRun(t, runDirs, runPrefix+"live"))
	keep := []string{filepath.Join(runDirs, runPrefix+"live"), mkRun(t, runDirs, "."+runPrefix+"new"), mkRun(t, runDirs, "other")}
	engine := fakeEngine(t, runPrefix+"stale", runPrefix+"live", runPrefix+"gone", "other-container", runPrefix+"x/../../evil")
	var swept []string
	o := opts
	o.Swept = func(run string) { swept = append(swept, run) }

	_, stop, err := runtime(answering{engine}, engine).Start(t.Context(), "127.0.0.1:0", o)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := stop(); err != nil {
			t.Error(err)
		}
	})
	want := []string{runPrefix + "gone", runPrefix + "stale"}
	if slices.Sort(swept); !slices.Equal(swept, want) {
		t.Errorf("swept %q, want %q", swept, want)
	}
	b, err := os.ReadFile(engine + ".rm")
	if err != nil {
		t.Fatal(err)
	}
	if removed := strings.Fields(string(b)); !slices.Equal(slices.Sorted(slices.Values(removed)), want) {
		t.Errorf("containers removed: %q, want %q", removed, want)
	}
	if exists(t, stale) {
		t.Error("the stale run directory, with its Share payload, survived")
	}
	for _, dir := range keep {
		if !exists(t, dir) {
			t.Errorf("%s was swept", dir)
		}
	}
}

// With a native KBS there is no container, and no engine to ask.
func TestStartSweepsRunDirectoriesForANativeKBS(t *testing.T) {
	runDirs := tmpfsDir(t)
	t.Setenv("XDG_RUNTIME_DIR", runDirs)
	stale := mkRun(t, runDirs, runPrefix+"stale")
	kbs := fakeExecutable(t, "kbs", "exec sleep 60")
	var swept []string
	o := opts
	o.KBSBinary = kbs
	o.Swept = func(run string) { swept = append(swept, run) }

	_, stop, err := runtime(answering{kbs}, "").Start(t.Context(), "127.0.0.1:0", o)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := stop(); err != nil {
			t.Error(err)
		}
	})
	if exists(t, stale) || !slices.Equal(swept, []string{runPrefix + "stale"}) {
		t.Errorf("stale run directory left: %v, swept %q", exists(t, stale), swept)
	}
}

// Start stops before it starts anything when it can't list, check or remove
// what earlier runs left. A run directory goes only after its container,
// which may still serve the Share payload.
func TestStartStopsWhenItCannotSweep(t *testing.T) {
	for name, tc := range map[string]struct {
		breakSweep func(t *testing.T, engine, stale string)
		want       string
	}{
		"ps fails": {func(t *testing.T, engine, _ string) {
			if err := os.Remove(engine + ".ps"); err != nil {
				t.Fatal(err)
			}
		}, "list the containers"},
		"rm fails": {func(t *testing.T, engine, _ string) {
			if err := os.WriteFile(engine+".rmfail", nil, 0o600); err != nil {
				t.Fatal(err)
			}
		}, "remove the container"},
		"a run directory it can't open": {func(t *testing.T, _, stale string) {
			if os.Getuid() == 0 {
				t.Skip("root opens any directory")
			}
			if err := os.Chmod(stale, 0); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := os.Chmod(stale, 0o700); err != nil {
					t.Error(err)
				}
			})
		}, "check an earlier Operator Verifier run"},
	} {
		t.Run(name, func(t *testing.T) {
			runDirs := tmpfsDir(t)
			t.Setenv("XDG_RUNTIME_DIR", runDirs)
			stale := mkRun(t, runDirs, runPrefix+"stale")
			engine := fakeEngine(t, runPrefix+"stale")
			tc.breakSweep(t, engine, stale)

			_, _, err := runtime(answering{engine}, engine).Start(t.Context(), "127.0.0.1:0", opts)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("Start = %v, want %q", err, tc.want)
			}
			if !exists(t, stale) {
				t.Error("the run directory went before its container")
			}
			if exists(t, engine+".args") {
				t.Error("KBS started")
			}
		})
	}
}

// A run holds its directory while it lives, so a second run's sweep leaves
// the first alone.
func TestStartLeavesALiveRunAlone(t *testing.T) {
	t.Setenv("XDG_RUNTIME_DIR", tmpfsDir(t))
	var dirs []string
	for _, name := range []string{"kbs1", "kbs2"} {
		kbs := fakeExecutable(t, name, "exec sleep 60")
		o := opts
		o.KBSBinary = kbs
		o.Swept = func(run string) { t.Errorf("swept the live run %s", run) }
		_, stop, err := runtime(answering{kbs}, "").Start(t.Context(), "127.0.0.1:0", o)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if err := stop(); err != nil {
				t.Error(err)
			}
		})
		dirs = append(dirs, filepath.Dir(recordedArgs(t, kbs)[1]))
	}
	for _, dir := range dirs {
		if !exists(t, dir) {
			t.Errorf("%s went while its run lives", dir)
		}
	}
}

// startAndHangEnv makes the test binary stand in for approve: it starts the
// Operator Verifier with the fake KBS it names, says so, and waits to be
// killed.
const startAndHangEnv = "VERIFIER_TEST_START_AND_HANG"

// AT-18 under SIGKILL (ticket 20): when the process that started the
// Operator Verifier dies without stopping it, the kernel sends KBS, or the
// engine, SIGTERM, as stop does.
func TestKBSGetsSIGTERMWhenApproveIsKilled(t *testing.T) {
	if kbs := os.Getenv(startAndHangEnv); kbs != "" {
		o := opts
		o.KBSBinary = kbs
		if _, _, err := runtime(answering{kbs}, "").Start(t.Context(), "127.0.0.1:0", o); err != nil {
			t.Fatal(err)
		}
		fmt.Println("started")
		time.Sleep(time.Minute)
		return
	}
	runDirs := tmpfsDir(t)
	kbs := fakeExecutable(t, "kbs", `trap 'kill $!; : >"$0.term"; exit' TERM; sleep 60 & wait $!`)
	approve := exec.Command(os.Args[0], "-test.run=^TestKBSGetsSIGTERMWhenApproveIsKilled$")
	approve.Env = append(os.Environ(), startAndHangEnv+"="+kbs, "XDG_RUNTIME_DIR="+runDirs)
	var stderr strings.Builder
	approve.Stderr = &stderr
	stdout, err := approve.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := approve.Start(); err != nil {
		t.Fatal(err)
	}
	line, _ := bufio.NewReader(stdout).ReadString('\n')
	if err := approve.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = approve.Wait() // killed
	if line != "started\n" {
		t.Fatalf("the approve stand-in printed %q: %s", line, stderr.String())
	}
	for range 100 {
		if exists(t, kbs+".term") {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Error("KBS got no SIGTERM after the process that started it was killed")
}

func TestStartReportsKBSFailure(t *testing.T) {
	runDirs := tmpfsDir(t)
	t.Setenv("XDG_RUNTIME_DIR", runDirs)
	o := opts
	o.KBSBinary = fakeExecutable(t, "kbs", "echo 'bad config' >&2; exit 1")

	_, _, err := runtime(silent{}, "").Start(t.Context(), "127.0.0.1:0", o)
	if err == nil || !strings.Contains(err.Error(), "bad config") {
		t.Errorf("Start = %v, want KBS's output", err)
	}
	if entries, err := os.ReadDir(runDirs); err != nil || len(entries) != 0 {
		t.Errorf("run directory left behind: %v", entries)
	}
}

// KBS output is held in memory until KBS answers, so only its tail is kept:
// the end, where a failing KBS says why.
func TestStartKeepsTheTailOfKBSOutput(t *testing.T) {
	t.Setenv("XDG_RUNTIME_DIR", tmpfsDir(t))
	o := opts
	o.KBSBinary = fakeExecutable(t, "kbs", "head -c 200000 /dev/zero | tr '\\0' '#'; echo; echo 'bad config' >&2; exit 1")

	_, _, err := runtime(silent{}, "").Start(t.Context(), "127.0.0.1:0", o)
	if err == nil || !strings.HasSuffix(err.Error(), "#\nbad config") {
		t.Fatalf("Start = %.100q..., want it to end with KBS's last words", err)
	}
	// 64 KiB of output, less "\nbad config\n".
	if got := strings.Count(err.Error(), "#"); got != 65536-12 {
		t.Errorf("Start error holds %d bytes of earlier KBS output, want %d", got, 65536-12)
	}
}

// The Share payload goes into the run directory, so it must be in memory.
func TestStartRefusesARunDirectoryOffTmpfs(t *testing.T) {
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	var st syscall.Statfs_t
	if err := syscall.Statfs(wd, &st); err != nil || st.Type == tmpfsMagic {
		t.Skipf("the source tree is on tmpfs or unreadable (%v)", err)
	}
	for parent, want := range map[string]string{wd: "is not on tmpfs", filepath.Join(wd, "missing"): "check run directory"} {
		t.Setenv("XDG_RUNTIME_DIR", parent)
		kbs := fakeExecutable(t, "kbs", "exec sleep 60")
		o := opts
		o.KBSBinary = kbs

		_, _, err := runtime(answering{kbs}, "").Start(t.Context(), "127.0.0.1:0", o)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("run directory in %s: Start = %v, want %q", parent, err, want)
		}
		left, err := filepath.Glob(filepath.Join(wd, "trustee-bootstrap-verifier-*"))
		if err != nil {
			t.Fatal(err)
		}
		if len(left) != 0 {
			t.Errorf("Start created %v", left)
			for _, d := range left {
				if err := os.RemoveAll(d); err != nil {
					t.Error(err)
				}
			}
		}
		if _, err := os.Stat(kbs + ".args"); err == nil {
			t.Error("KBS started")
		}
	}
}

// AT-02: the Operator Verifier is never reachable from the network.
func TestStartRefusesANonLoopbackAddress(t *testing.T) {
	t.Setenv("XDG_RUNTIME_DIR", tmpfsDir(t))
	kbs := fakeExecutable(t, "kbs", "exec sleep 60")
	o := opts
	o.KBSBinary = kbs

	_, _, err := runtime(answering{kbs}, "").Start(t.Context(), "0.0.0.0:0", o)
	if err == nil || !strings.Contains(err.Error(), "127.0.0.1") {
		t.Errorf("Start on 0.0.0.0 = %v, want a refusal", err)
	}
	if _, err := os.Stat(kbs + ".args"); err == nil {
		t.Error("KBS started")
	}
}

func TestDefaultEngine(t *testing.T) {
	bin := t.TempDir()
	t.Setenv("PATH", bin)
	if got := verifier.DefaultEngine(); got != "docker" {
		t.Errorf("without podman: %s, want docker", got)
	}
	if err := os.WriteFile(filepath.Join(bin, "podman"), nil, 0o700); err != nil {
		t.Fatal(err)
	}
	if got := verifier.DefaultEngine(); got != "podman" {
		t.Errorf("with podman: %s, want podman", got)
	}
}
