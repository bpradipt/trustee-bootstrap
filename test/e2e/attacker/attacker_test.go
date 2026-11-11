// Package attacker holds the attacks of a relay holder and of the host on
// the Operator Verifier and the unlocked Trustee (AT-05, AT-21, AT-22), for
// test/e2e/share-release.sh and test/e2e/trustee-cvm.sh. It is a test so it
// never ships. The scripts build it with `go test -c` and pick the attack
// with -attack; under plain `go test` it skips. The test fails when the
// target releases anything or takes the admin call.
//
// Through a relay (-listen): the attacker poses as the Bootstrap Helper at
// -listen, passes the real helper's (-helper) status through, and attacks
// over the relay that `approve` opens to it.
//
//	forge       a self-signed token naming the attacker's TEE key (AT-21)
//	admin       replace the resource policy without the admin key (AT-22)
//	hold        keep the relay open and do nothing, until approve leaves
//	pass        relay the real helper's attestation untouched; record it
//	tee-pubkey  relay it with the attacker's TEE key in place of the CVM's (AT-05)
//	replay      relay it with the recorded attestation from pass (AT-05)
//
// Directly (-kbs): forge and admin against a KBS URL, the unlocked Trustee.
package attacker

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/confidential-devhub/trustee-bootstrap/internal/memnet"
	"github.com/confidential-devhub/trustee-bootstrap/pkg/helper"
	"github.com/confidential-devhub/trustee-bootstrap/pkg/relay"
	"github.com/confidential-devhub/trustee-bootstrap/pkg/verifier"
)

var (
	attack    = flag.String("attack", "", "forge, admin, hold, pass, tee-pubkey or replay")
	listen    = flag.String("listen", "", "pose as the Bootstrap Helper here and attack through the relay approve opens")
	helperURL = flag.String("helper", "", "the real Bootstrap Helper")
	kbsURL    = flag.String("kbs", "", "attack this KBS directly instead")
	resource  = flag.String("resource", verifier.ShareResource, "the KBS resource to ask for")
	pcr8      = flag.String("pcr8", "", "forge: the init_data claim the target's resource policy wants")
	ak        = flag.String("ak", "", "forge: the ak_public claim")
	unchanged = flag.String("policy-unchanged", "", "admin through a relay: the Operator Verifier's resource policy must still equal this file")
	evidence  = flag.String("evidence", "", "pass records the genuine attestation request here; replay sends it again")
)

func TestAttack(t *testing.T) {
	if *attack == "" {
		t.Skip("run by the e2e scripts with -attack")
	}
	if *kbsURL != "" {
		// The attacker does not care whose certificate Trustee shows.
		c := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
		kbsAttack(t, c, *kbsURL)
		return
	}
	poseAsHelper(t)
}

// poseAsHelper serves one relay at -listen, then returns.
func poseAsHelper(t *testing.T) {
	l, err := net.Listen("tcp", *listen)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+helper.StatusPath, proxyStatus)
	mux.HandleFunc("GET "+helper.RelayPath, func(w http.ResponseWriter, r *http.Request) {
		defer close(done)
		ws, err := websocket.Accept(w, r, nil)
		if err != nil {
			t.Error(err)
			return
		}
		t.Log("relay open")
		onRelay(t, r.Context(), ws)
	})
	srv := &http.Server{Handler: mux}
	go srv.Serve(l)
	<-done
	srv.Close()
}

// proxyStatus passes the real Bootstrap Helper's status through, so
// approve sees the key_id and index it expects.
func proxyStatus(w http.ResponseWriter, r *http.Request) {
	u, err := url.JoinPath(*helperURL, helper.StatusPath)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	resp, err := http.Get(u)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

func onRelay(t *testing.T, ctx context.Context, ws *websocket.Conn) {
	switch *attack {
	case "hold":
		_, _, err := ws.Read(ctx)
		t.Logf("approve left the relay: %v", err)
	case "pass", "tee-pubkey", "replay":
		manInTheMiddle(t, ctx, ws)
	default:
		kbsAttack(t, throughRelay(ctx, ws), "http://operator-verifier")
		checkPolicyUnchanged(t)
		ws.Close(websocket.StatusPolicyViolation, "attack done")
	}
}

// throughRelay returns a client that reaches the operator's Operator
// Verifier over the relay, as the Bootstrap Helper's guest proxy would.
func throughRelay(ctx context.Context, ws *websocket.Conn) *http.Client {
	var n memnet.Network
	proxy, _ := n.Listen("tcp", "proxy")
	go relay.Guest(ctx, ws, proxy, relay.DefaultLimits())
	dial := func(ctx context.Context, _, _ string) (net.Conn, error) { return n.DialContext(ctx, "tcp", "proxy") }
	return &http.Client{Transport: &http.Transport{DialContext: dial}}
}

func kbsAttack(t *testing.T, c *http.Client, base string) {
	switch *attack {
	case "forge":
		code, body := call(t, c, http.MethodGet, base+"/kbs/v0/resource/"+*resource, "Bearer "+forgedToken(t), nil)
		t.Logf("forged token: HTTP %d %s", code, body)
		if code == http.StatusOK {
			t.Errorf("KBS released %s to a forged token naming the attacker's TEE key", *resource)
		}
	case "admin":
		allowAll := base64.RawURLEncoding.EncodeToString([]byte("package policy\n\ndefault allow := true\n"))
		body, _ := json.Marshal(map[string]string{"policy": allowAll})
		for name, auth := range map[string]string{"no admin token": "", "the attacker's admin token": "Bearer " + adminToken(t)} {
			code, resp := call(t, c, http.MethodPost, base+"/kbs/v0/resource-policy", auth, body)
			t.Logf("resource policy replacement with %s: HTTP %d %s", name, code, resp)
			if code == http.StatusOK {
				t.Errorf("KBS took a resource policy replacement with %s", name)
			}
		}
	default:
		t.Fatalf("unknown attack %q", *attack)
	}
}

func call(t *testing.T, c *http.Client, method, u, auth string, body []byte) (int, string) {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), method, u, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 300))
	return resp.StatusCode, string(b)
}

// checkPolicyUnchanged compares the resource policy the running Operator
// Verifier serves from with the operator's.
func checkPolicyUnchanged(t *testing.T) {
	if *unchanged == "" {
		return
	}
	want, err := os.ReadFile(*unchanged)
	if err != nil {
		t.Fatal(err)
	}
	parent := os.Getenv("XDG_RUNTIME_DIR")
	if parent == "" {
		parent = "/dev/shm"
	}
	paths, _ := filepath.Glob(filepath.Join(parent, "trustee-bootstrap-verifier-*", verifier.ResourcePolicyPath))
	if len(paths) != 1 {
		t.Fatalf("Operator Verifier resource policies: %v, want one", paths)
	}
	got, err := os.ReadFile(paths[0])
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("the Operator Verifier's resource policy changed:\n%s", got)
	} else {
		t.Log("the Operator Verifier's resource policy is unchanged")
	}
}

// manInTheMiddle relays between the real Bootstrap Helper and approve at
// the HTTP level, tampering with the CDH's attestation request.
func manInTheMiddle(t *testing.T, ctx context.Context, operator *websocket.Conn) {
	verifierClient := throughRelay(ctx, operator)
	u, err := url.JoinPath(*helperURL, helper.RelayPath)
	if err != nil {
		t.Fatal(err)
	}
	guest, _, err := websocket.Dial(ctx, u, nil)
	if err != nil {
		t.Error(err)
		operator.Close(websocket.StatusInternalError, "attacker could not reach the helper")
		return
	}
	var n memnet.Network
	l, _ := n.Listen("tcp", "mitm")
	m := &tamperer{t: t}
	go http.Serve(l, &httputil.ReverseProxy{Rewrite: m.rewrite, ModifyResponse: m.observe, Transport: verifierClient.Transport})
	err = relay.Operator(ctx, guest, func(ctx context.Context) (net.Conn, error) {
		return n.DialContext(ctx, "tcp", "mitm")
	}, relay.DefaultLimits())
	// approve hears how the helper ended the relay.
	var ce websocket.CloseError
	if !errors.As(err, &ce) {
		ce = websocket.CloseError{Code: websocket.StatusInternalError, Reason: "relay failed"}
	}
	t.Logf("the helper ended the relay: %d %s", ce.Code, ce.Reason)
	operator.Close(ce.Code, ce.Reason)
	m.verdict()
}

type tamperer struct {
	t        *testing.T
	mu       sync.Mutex
	tampered int  // attestation requests rewritten (or recorded, for pass)
	released bool // the Operator Verifier answered a resource request with 200
}

func (m *tamperer) rewrite(pr *httputil.ProxyRequest) {
	pr.SetURL(&url.URL{Scheme: "http", Host: "operator-verifier"})
	if pr.In.URL.Path != "/kbs/v0/attest" {
		return
	}
	body, err := io.ReadAll(pr.In.Body)
	if err != nil {
		m.t.Error(err)
		return
	}
	if b, ok := m.tamper(body); ok {
		body = b
		m.mu.Lock()
		m.tampered++
		m.mu.Unlock()
	}
	// GetBody lets the transport resend it on a fresh inner connection.
	pr.Out.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(body)), nil }
	pr.Out.Body, _ = pr.Out.GetBody()
	pr.Out.ContentLength = int64(len(body))
}

// tamper rewrites one KBS Attestation message (kbs-types 0.18:
// {"runtime-data": {"nonce", "tee-pubkey"}, "tee-evidence", ...}). pass
// re-encodes it unchanged, so the tampered runs differ from it only in
// what they change.
func (m *tamperer) tamper(body []byte) ([]byte, bool) {
	var msg map[string]any
	if err := json.Unmarshal(body, &msg); err != nil {
		m.t.Errorf("attestation request: %v", err)
		return nil, false
	}
	rd, ok := msg["runtime-data"].(map[string]any)
	if !ok {
		m.t.Errorf("attestation request has no runtime-data: %.200s", body)
		return nil, false
	}
	switch *attack {
	case "pass":
		if err := os.WriteFile(*evidence, body, 0o600); err != nil {
			m.t.Error(err)
		}
	case "tee-pubkey":
		rd["tee-pubkey"] = teeKey(m.t)
	case "replay":
		// The recorded evidence and TEE key, with this session's nonce, so
		// only the evidence binding can catch it.
		var old map[string]any
		b, err := os.ReadFile(*evidence)
		if err == nil {
			err = json.Unmarshal(b, &old)
		}
		oldRD, ok := old["runtime-data"].(map[string]any)
		if err != nil || !ok {
			m.t.Errorf("recorded attestation: %v", err)
			return nil, false
		}
		oldRD["nonce"] = rd["nonce"]
		msg = old
	}
	b, err := json.Marshal(msg)
	if err != nil {
		m.t.Error(err)
		return nil, false
	}
	return b, true
}

func (m *tamperer) observe(resp *http.Response) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.t.Logf("%s %s: HTTP %d", resp.Request.Method, resp.Request.URL.Path, resp.StatusCode)
	if strings.HasPrefix(resp.Request.URL.Path, "/kbs/v0/resource/") && resp.StatusCode == http.StatusOK {
		m.released = true
	}
	return nil
}

func (m *tamperer) verdict() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.tampered == 0 {
		m.t.Errorf("%s: saw no attestation request", *attack)
	}
	if *attack == "pass" {
		if !m.released {
			m.t.Error("pass: the genuine CVM got no release through the attacker, so the attacks prove nothing")
		}
		return
	}
	if m.released {
		m.t.Errorf("%s: the Operator Verifier released the Share", *attack)
	}
}

// teeKey is a fresh attacker TEE key as a KBS TeePubKey: a JWE for it is
// readable by the attacker.
func teeKey(t *testing.T) map[string]any {
	k := ecKey(t)
	jwk := ecJWK(t, k)
	jwk["alg"] = "ECDH-ES+A256KW"
	return jwk
}

// forgedToken is an EAR-shaped attestation token with the claims the
// target's resource policy wants and the attacker's TEE key, signed by the
// attacker. Its header carries the signing key (jwk) with a self-signed
// certificate (x5c): KBS with insecure_header_jwk = true would accept it.
func forgedToken(t *testing.T) string {
	signer := ecKey(t)
	jwk := ecJWK(t, signer)
	jwk["alg"] = "ES256"
	jwk["x5c"] = []string{base64.StdEncoding.EncodeToString(selfSigned(t, signer))}
	now := time.Now().Unix()
	claims := map[string]any{
		"iat": now,
		"exp": now + 3600,
		"submods": map[string]any{"cpu0": map[string]any{
			"ear.status": "affirming",
			"ear.veraison.annotated-evidence": map[string]any{
				"init_data":           *pcr8,
				"tpm":                 map[string]any{"ak_public": *ak, "pcr11": strings.Repeat("0", 64)},
				"runtime_data_claims": map[string]any{"tee-pubkey": teeKey(t)},
			},
		}},
	}
	return jwt(t, map[string]any{"alg": "ES256", "typ": "JWT", "jwk": jwk}, claims, func(in []byte) []byte {
		d := sha256.Sum256(in)
		r, s, err := ecdsa.Sign(rand.Reader, signer, d[:])
		if err != nil {
			t.Fatal(err)
		}
		return append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...)
	})
}

// adminToken is an admin token signed by a key the attacker made.
func adminToken(t *testing.T) string {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().Unix()
	return jwt(t, map[string]any{"alg": "EdDSA", "typ": "JWT"}, map[string]any{"iat": now, "exp": now + 3600},
		func(in []byte) []byte { return ed25519.Sign(key, in) })
}

func jwt(t *testing.T, header, claims any, sign func([]byte) []byte) string {
	h, err := json.Marshal(header)
	if err != nil {
		t.Fatal(err)
	}
	c, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	in := base64.RawURLEncoding.EncodeToString(h) + "." + base64.RawURLEncoding.EncodeToString(c)
	return in + "." + base64.RawURLEncoding.EncodeToString(sign([]byte(in)))
}

func ecKey(t *testing.T) *ecdsa.PrivateKey {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func ecJWK(t *testing.T, k *ecdsa.PrivateKey) map[string]any {
	pub, err := k.PublicKey.ECDH()
	if err != nil {
		t.Fatal(err)
	}
	b := pub.Bytes() // 0x04 || X || Y
	return map[string]any{
		"kty": "EC",
		"crv": "P-256",
		"x":   base64.RawURLEncoding.EncodeToString(b[1:33]),
		"y":   base64.RawURLEncoding.EncodeToString(b[33:]),
	}
}

func selfSigned(t *testing.T, k *ecdsa.PrivateKey) []byte {
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "attacker"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	return der
}
