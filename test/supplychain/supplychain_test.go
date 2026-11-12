// Package supplychain keeps the release free of test code and every image
// and CI action pinned. `go test ./...` runs it, so CI does on every PR.
package supplychain_test

import (
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/confidential-devhub/trustee-bootstrap/pkg/verifier"
)

// root is the repository root, from this package's directory.
const root = "../.."

const module = "github.com/confidential-devhub/trustee-bootstrap"

// testOnly are packages that must never reach a release binary.
var testOnly = []string{
	"testing",
	"net/http/httptest",
	module + "/internal/memnet",
	module + "/internal/trusteetest",
}

// The release binaries link no test package: no in-memory network, no test
// fixtures, nothing under test/ (the attacker, the claim-profile harness).
func TestReleaseBinariesLinkNoTestCode(t *testing.T) {
	cmd := exec.Command("go", "list", "-deps", "./cmd/trustee-bootstrap", "./cmd/bootstrap-helper")
	cmd.Dir = root
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("go list: %v", err)
	}
	deps := strings.Fields(string(out))
	if len(deps) < 50 {
		t.Fatalf("go list -deps gave %d packages; it missed the binaries", len(deps))
	}
	for _, dep := range deps {
		if isTestOnly(dep) {
			t.Errorf("a release binary links %s", dep)
		}
	}
}

func isTestOnly(pkg string) bool {
	for _, p := range testOnly {
		if pkg == p || strings.HasPrefix(pkg, p+"/") {
			return true
		}
	}
	return strings.HasPrefix(pkg, module+"/test/")
}

func TestIsTestOnly(t *testing.T) {
	for pkg, want := range map[string]bool{
		"testing":                     true,
		"testing/fstest":              true,
		"net/http/httptest":           true,
		module + "/internal/memnet":   true,
		module + "/test/e2e/attacker": true,
		"net/http":                    false,
		"testingfoo":                  false,
		module + "/internal/audit":    false,
		module + "/pkg/helper":        false,
	} {
		if got := isTestOnly(pkg); got != want {
			t.Errorf("isTestOnly(%s) = %v, want %v", pkg, got, want)
		}
	}
}

// Everything under test/ is a _test.go file, so nothing there can be
// imported, built into a binary or given a flag a release reads.
func TestTestTreeHoldsOnlyTestFiles(t *testing.T) {
	err := filepath.WalkDir(filepath.Join(root, "test"), func(path string, d fs.DirEntry, err error) error {
		if err == nil && strings.HasSuffix(path, ".go") && !strings.HasSuffix(path, "_test.go") {
			t.Errorf("%s is not a _test.go file", path)
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
}

var (
	digest = `@sha256:[0-9a-f]{64}`
	// An image on a public registry, with its tag and digest if it has them.
	imageRef = regexp.MustCompile(`\b(?:docker\.io|ghcr\.io|quay\.io|gcr\.io|registry\.k8s\.io|mcr\.microsoft\.com|kindest)/[\w./-]+(?::[\w.-]+)?(?:@sha256:[0-9a-f]*)?`)
	pinned   = regexp.MustCompile(digest + `$`)
	// A Containerfile stage: FROM <image>.
	fromLine = regexp.MustCompile(`(?m)^FROM\s+(\S+)`)
	// A Kubernetes container image: image: <image>. A $VAR or an @NAME@
	// placeholder names an image pinned elsewhere.
	imageLine   = regexp.MustCompile(`(?m)^\s*-?\s*image:\s*(\S+)`)
	placeholder = regexp.MustCompile(`^(\$\w+|"@\w+@")$`)
	// A GitHub Actions step: uses: <action>@<ref>.
	usesLine = regexp.MustCompile(`(?m)^\s*-?\s*uses:\s*(\S+)`)
	fullSHA  = regexp.MustCompile(`@[0-9a-f]{40}$`)
)

// e2eGuest is the one image pulled by tag, not digest. Its tag is the sha256
// of the files that build it (test/e2e/guest-build.sh), and only the
// e2e-guest workflow pushes it.
const e2eGuest = "ghcr.io/confidential-devhub/trustee-bootstrap-e2e-guest"

func isE2EGuest(ref string) bool {
	return ref == e2eGuest || strings.HasPrefix(ref, e2eGuest+":")
}

// Every container image is pinned by digest and every CI action by commit
// SHA, in the code, scripts, manifests and workflows.
func TestImagesAndActionsArePinned(t *testing.T) {
	for path, body := range sources(t) {
		for _, ref := range imageRef.FindAllString(body, -1) {
			if !pinned.MatchString(ref) && !isE2EGuest(ref) {
				t.Errorf("%s: image %s is not pinned by digest", path, ref)
			}
		}
		for _, m := range fromLine.FindAllStringSubmatch(body, -1) {
			if m[1] != "scratch" && !pinned.MatchString(m[1]) {
				t.Errorf("%s: FROM %s is not pinned by digest", path, m[1])
			}
		}
		for _, m := range imageLine.FindAllStringSubmatch(body, -1) {
			if !placeholder.MatchString(m[1]) && !pinned.MatchString(m[1]) {
				t.Errorf("%s: image: %s is not pinned by digest", path, m[1])
			}
		}
		for _, m := range usesLine.FindAllStringSubmatch(body, -1) {
			if !fullSHA.MatchString(m[1]) {
				t.Errorf("%s: uses %s is not pinned by commit SHA", path, m[1])
			}
		}
	}
}

func TestPinCheckCatchesUnpinnedReferences(t *testing.T) {
	// Split, so that the pin check does not find them in this file.
	for _, ref := range []string{"ghcr" + ".io/x/kbs:v1", "docker" + ".io/library/busybox:1.37.0@sha256:abc", "kindest" + "/node:v1.37.0"} {
		if m := imageRef.FindString(ref); m == "" || pinned.MatchString(m) {
			t.Errorf("%s passes as pinned", ref)
		}
	}
	if m := imageLine.FindStringSubmatch("    - image: busybox"); m == nil || placeholder.MatchString(m[1]) || pinned.MatchString(m[1]) {
		t.Error("image: busybox passes as pinned")
	}
	if fullSHA.MatchString("actions/checkout@v7") {
		t.Error("an action tag passes as pinned")
	}
}

// Only the e2e guest repository itself escapes the digest rule.
func TestE2EGuestExemption(t *testing.T) {
	for ref, want := range map[string]bool{
		e2eGuest:               true,
		e2eGuest + ":0123abcd": true,
		e2eGuest + "x:v1":      false,
		e2eGuest + "/other:v1": false,
		"ghcr" + ".io/other/trustee-bootstrap-e2e-guest:v1": false,
	} {
		if got := isE2EGuest(ref); got != want {
			t.Errorf("isE2EGuest(%s) = %v, want %v", ref, got, want)
		}
	}
}

// versions.yaml holds the values the e2e scripts use, and
// docs/upstream-pins.md gives the source of each. Every value appears in the
// doc (an image by its digest), and the CLI's Operator Verifier runs the KBS
// image that the e2e tests run.
func TestVersionsMatchUpstreamPins(t *testing.T) {
	versions := readVersions(t)
	doc := readFile(t, "docs/upstream-pins.md")
	for key, value := range versions {
		want := value
		if _, digest, ok := strings.Cut(value, "@"); ok {
			want = digest
		}
		if !strings.Contains(doc, want) {
			t.Errorf("versions.yaml %s: %s is not in docs/upstream-pins.md", key, want)
		}
	}
	if versions["kbs_image"] != verifier.Image {
		t.Errorf("versions.yaml kbs_image is %s, verifier.Image is %s", versions["kbs_image"], verifier.Image)
	}
}

// readVersions parses versions.yaml as the scripts' awk reader does: comment
// lines, blank lines, and one bare "key: value" per line.
func readVersions(t *testing.T) map[string]string {
	t.Helper()
	versions := map[string]string{}
	for i, line := range strings.Split(readFile(t, "versions.yaml"), "\n") {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, ": ")
		if !ok || value == "" || strings.ContainsAny(key+value, " \t\"'#") {
			t.Fatalf("versions.yaml:%d: want a bare \"key: value\", got %q", i+1, line)
		}
		if _, dup := versions[key]; dup {
			t.Fatalf("versions.yaml:%d: %s appears twice", i+1, key)
		}
		versions[key] = value
	}
	if len(versions) < 10 {
		t.Fatalf("read %d pins from versions.yaml; the parse missed them", len(versions))
	}
	return versions
}

func readFile(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(root, name))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// sources reads the files that can name an image or an action.
func sources(t *testing.T) map[string]string {
	t.Helper()
	files := map[string]string{}
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && (d.Name() == ".git" || d.Name() == ".scratch") {
			return filepath.SkipDir
		}
		switch ext := filepath.Ext(path); {
		case d.IsDir():
		case ext == ".go", ext == ".sh", ext == ".yaml", ext == ".yml", ext == ".toml", ext == ".json",
			strings.HasPrefix(d.Name(), "Containerfile"), strings.HasPrefix(d.Name(), "Dockerfile"):
			b, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			files[path] = string(b)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(files) < 20 {
		t.Fatalf("found %d source files; the walk missed the repository", len(files))
	}
	return files
}
