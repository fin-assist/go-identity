package identity

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func writeKey(t *testing.T, key ed25519.PrivateKey) string {
	t.Helper()
	b, e := x509.MarshalPKCS8PrivateKey(key)
	if e != nil {
		t.Fatal(e)
	}
	path := filepath.Join(t.TempDir(), "key.pem")
	if e = os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: b}), 0600); e != nil {
		t.Fatal(e)
	}
	return path
}
func TestStageSource(t *testing.T) {
	now := time.Unix(1700000000, 0)
	pub, key := testKey(t)
	o := StageOptions{KeyFile: writeKey(t, key), Caller: "bank-bff", Issuer: "stage", Clock: func() time.Time { return now }}
	s, e := NewStageSource("stage", o)
	if e != nil {
		t.Fatal(e)
	}
	v, e := NewStageVerifier("stage", VerifyOptions{Issuer: "stage", Audience: "finassist-internal", Clock: o.Clock}, map[string]ed25519.PublicKey{"bank-bff": pub})
	if e != nil {
		t.Fatal(e)
	}
	first, e := s.Token(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	if id, e := v.VerifyService(context.Background(), first); e != nil || id != "bank-bff" {
		t.Fatal(id, e)
	}
	var wg sync.WaitGroup
	for range 20 {
		wg.Go(func() {
			raw, e := s.Token(context.Background())
			if e != nil || raw != first {
				t.Error("cache failed", e)
			}
		})
	}
	wg.Wait()
	now = now.Add(49 * time.Second)
	second, e := s.Token(context.Background())
	if e != nil || first == second {
		t.Fatal("token not rotated", e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e = s.Token(ctx); e == nil {
		t.Fatal("cancel ignored")
	}
	if _, e = NewStageSource("prod", o); e == nil {
		t.Fatal("stage key allowed in prod")
	}
	for _, mutate := range []func(*StageOptions){func(o *StageOptions) { o.TTL = 6 * time.Minute }, func(o *StageOptions) { o.Clock = nil }, func(o *StageOptions) { o.Caller = "-" }, func(o *StageOptions) { o.Issuer = "" }, func(o *StageOptions) { o.KeyFile = "/nonexistent/secret" }} {
		x := o
		mutate(&x)
		if _, e = NewStageSource("stage", x); e == nil {
			t.Fatal("bad source accepted")
		} else if strings.Contains(e.Error(), "/nonexistent") {
			t.Fatal("path leaked")
		}
	}
	for _, data := range []string{"bad", strings.Repeat("x", 8193), string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("bad")})), string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pub}))} {
		if e = os.WriteFile(o.KeyFile, []byte(data), 0600); e != nil {
			t.Fatal(e)
		}
		if _, e = NewStageSource("dev", o); e == nil {
			t.Fatal("bad PEM accepted")
		}
	}
}

func TestProjectedRotation(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "v1")
	path := filepath.Join(dir, "token")
	if e := os.WriteFile(target, []byte("first\n"), 0600); e != nil {
		t.Fatal(e)
	}
	if e := os.Symlink(target, path); e != nil {
		t.Fatal(e)
	}
	s, e := NewProjectedSource(path)
	if e != nil {
		t.Fatal(e)
	}
	for range 2 {
		if token, e := s.Token(context.Background()); e != nil || token != "first" {
			t.Fatal(token, e)
		}
	}
	info, e := os.Stat(target)
	if e != nil {
		t.Fatal(e)
	}
	next := filepath.Join(dir, "v2")
	if e = os.WriteFile(next, []byte("other\n"), 0600); e != nil {
		t.Fatal(e)
	}
	if e = os.Chtimes(next, info.ModTime(), info.ModTime()); e != nil {
		t.Fatal(e)
	}
	replacement := filepath.Join(dir, "new")
	if e = os.Symlink(next, replacement); e != nil {
		t.Fatal(e)
	}
	if e = os.Rename(replacement, path); e != nil {
		t.Fatal(e)
	}
	if token, e := s.Token(context.Background()); e != nil || token != "other" {
		t.Fatal("symlink replacement ignored", token, e)
	}
	if e = os.Remove(path); e != nil {
		t.Fatal(e)
	}
	if _, e = s.Token(context.Background()); e == nil {
		t.Fatal("stale token returned")
	}
	for _, data := range []string{"", strings.Repeat("x", maxToken+3), "Bearer token", "first\nsecond"} {
		if e = os.WriteFile(path, []byte(data), 0600); e != nil {
			t.Fatal(e)
		}
		s, _ = NewProjectedSource(path)
		if _, e = s.Token(context.Background()); e == nil {
			t.Fatal("bad file accepted")
		}
	}
	s, _ = NewProjectedSource(dir)
	if _, e = s.Token(context.Background()); e == nil {
		t.Fatal("directory accepted")
	}
	if _, e = NewProjectedSource(""); e == nil {
		t.Fatal("empty path")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e = s.Token(ctx); e == nil {
		t.Fatal("cancel ignored")
	}
}
