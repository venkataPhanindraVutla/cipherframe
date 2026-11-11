package config

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log/slog"
	"math/big"
	"strings"
	"testing"
	"time"
)

const vaultTestToken = "hvs.TOKEN-distinct-qq17" //nolint:gosec // test fixture

func vaultEnv() env {
	return base.with(
		EnvKMSProvider, ProviderVault,
		EnvKMSVaultAddr, "https://vault.example.com:8200",
		EnvKMSVaultToken, vaultTestToken,
		EnvKMSVaultKeyName, "cipherframe",
	)
}

func testCAPEM(t *testing.T) string {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test ca"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func TestKMSVaultDefaults(t *testing.T) {
	c, err := load(vaultEnv(), nil)
	if err != nil {
		t.Fatal(err)
	}
	v := c.KMS.Vault
	if v.Addr != "https://vault.example.com:8200" || v.TransitMount != "transit" || v.KeyName != "cipherframe" ||
		v.Namespace != "" || v.CAFile != "" || v.Timeout != 5*time.Second || v.Token.Reveal() != vaultTestToken {
		t.Fatalf("unexpected settings: %+v", v)
	}
	if c.KMS.LocalKEKs.Len() != 0 {
		t.Fatal("local KEKs must be ignored when the provider is vault")
	}
}

func TestKMSVaultAllOptionsAndTokenFile(t *testing.T) {
	e := vaultEnv().with(
		EnvKMSVaultToken, "\x00", EnvKMSVaultToken+"_FILE", "/token",
		EnvKMSVaultTransitMount, "team/transit", EnvKMSVaultNamespace, "admin/team",
		EnvKMSVaultCAFile, "/ca.pem", EnvKMSVaultTimeout, "1500ms",
	)
	c, err := load(e, map[string]string{"/token": vaultTestToken + "\n", "/ca.pem": testCAPEM(t)})
	if err != nil {
		t.Fatal(err)
	}
	v := c.KMS.Vault
	if v.Token.Reveal() != vaultTestToken || v.TransitMount != "team/transit" || v.Namespace != "admin/team" ||
		v.CAFile != "/ca.pem" || v.Timeout != 1500*time.Millisecond {
		t.Fatalf("unexpected settings: %+v", v)
	}
}

func TestKMSVaultRules(t *testing.T) {
	tests := []struct {
		name  string
		env   env
		files map[string]string
		want  string
	}{
		{"addr missing", vaultEnv().with(EnvKMSVaultAddr, "\x00"), nil, EnvKMSVaultAddr},
		{"addr not a url", vaultEnv().with(EnvKMSVaultAddr, "vault:8200"), nil, "absolute http"},
		{"addr ftp", vaultEnv().with(EnvKMSVaultAddr, "ftp://vault"), nil, "absolute http"},
		{"addr with credentials", vaultEnv().with(EnvKMSVaultAddr, "https://u:p@vault"), nil, "must not contain"},
		{"addr with query", vaultEnv().with(EnvKMSVaultAddr, "https://vault?x=1"), nil, "must not contain"},
		{"token missing", vaultEnv().with(EnvKMSVaultToken, "\x00"), nil, EnvKMSVaultToken},
		{"token empty", vaultEnv().with(EnvKMSVaultToken, ""), nil, EnvKMSVaultToken},
		{"token with newline", vaultEnv().with(EnvKMSVaultToken, "a\nb"), nil, "whitespace"},
		{"token both", vaultEnv().with(EnvKMSVaultToken+"_FILE", "/t"), map[string]string{"/t": "x"}, "both set"},
		{"token file unreadable", vaultEnv().with(EnvKMSVaultToken, "\x00", EnvKMSVaultToken+"_FILE", "/nope"), nil, "cannot read"},
		{"key missing", vaultEnv().with(EnvKMSVaultKeyName, "\x00"), nil, EnvKMSVaultKeyName},
		{"key with slash", vaultEnv().with(EnvKMSVaultKeyName, "a/b"), nil, EnvKMSVaultKeyName},
		{"mount leading slash", vaultEnv().with(EnvKMSVaultTransitMount, "/transit"), nil, EnvKMSVaultTransitMount},
		{"mount trailing slash", vaultEnv().with(EnvKMSVaultTransitMount, "transit/"), nil, EnvKMSVaultTransitMount},
		{"mount empty segment", vaultEnv().with(EnvKMSVaultTransitMount, "a//b"), nil, EnvKMSVaultTransitMount},
		{"namespace control", vaultEnv().with(EnvKMSVaultNamespace, "a\r\nX: y"), nil, EnvKMSVaultNamespace},
		{"ca unreadable", vaultEnv().with(EnvKMSVaultCAFile, "/nope.pem"), nil, EnvKMSVaultCAFile},
		{"ca not pem", vaultEnv().with(EnvKMSVaultCAFile, "/ca.pem"), map[string]string{"/ca.pem": "nope"}, "no PEM"},
		{"timeout bad", vaultEnv().with(EnvKMSVaultTimeout, "5"), nil, "Go duration"},
		{"timeout zero", vaultEnv().with(EnvKMSVaultTimeout, "0s"), nil, "greater than zero"},
		{"timeout negative", vaultEnv().with(EnvKMSVaultTimeout, "-1s"), nil, "greater than zero"},
		{"timeout huge", vaultEnv().with(EnvKMSVaultTimeout, "24h"), nil, "at most"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := load(tc.env, tc.files)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want mention of %q", err, tc.want)
			}
			if strings.Contains(err.Error(), vaultTestToken) {
				t.Fatal("error leaks the token")
			}
		})
	}
}

func TestKMSVaultProduction(t *testing.T) {
	good := vaultEnv().with(EnvEnv, "production", EnvS3AccessKeyID, "", EnvS3SecretAccessKey, "")
	if _, err := load(good, nil); err != nil {
		t.Fatalf("valid production config rejected: %v", err)
	}
	tests := []struct {
		name string
		env  env
		want string
	}{
		{"http refused", good.with(EnvKMSVaultAddr, "http://vault:8200"), "https in production"},
		{"placeholder token", good.with(EnvKMSVaultToken, PlaceholderPrefix+"root"), "placeholder"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := load(tc.env, nil); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want mention of %q", err, tc.want)
			}
		})
	}
}

func TestKMSVaultDevelopmentAllowsHTTPAndPlaceholder(t *testing.T) {
	e := vaultEnv().with(EnvKMSVaultAddr, "http://localhost:8200", EnvKMSVaultToken, PlaceholderPrefix+"root")
	if _, err := load(e, nil); err != nil {
		t.Fatal(err)
	}
}

func TestKMSVaultRedaction(t *testing.T) {
	c, err := load(vaultEnv().with(EnvKMSVaultNamespace, "ns1"), nil)
	if err != nil {
		t.Fatal(err)
	}
	v := c.KMS.Vault
	forms := []string{
		fmt.Sprint(v), fmt.Sprintf("%v", v), fmt.Sprintf("%+v", v), fmt.Sprintf("%#v", v), fmt.Sprintf("%v", &v),
		fmt.Sprintf("%+v", c.KMS), fmt.Sprintf("%#v", c.KMS), fmt.Sprintf("%+v", c),
	}
	b, err := json.Marshal(c.KMS)
	if err != nil {
		t.Fatal(err)
	}
	forms = append(forms, string(b))
	var buf bytes.Buffer
	slog.New(slog.NewJSONHandler(&buf, nil)).Info("cfg", "vault", v, "config", c)
	forms = append(forms, buf.String())
	for _, f := range forms {
		if strings.Contains(f, vaultTestToken) {
			t.Fatalf("a printed form leaks the token: %.80s", f)
		}
	}
	out := buf.String()
	if !strings.Contains(out, "vault.example.com") || !strings.Contains(out, "cipherframe") || !strings.Contains(out, "ns1") {
		t.Fatalf("LogValue lacks addr, key name or namespace: %s", out)
	}
	line := v.LogValue().String()
	if strings.Contains(line, "ca_file") || strings.Contains(line, "timeout") {
		t.Fatalf("LogValue shows more than addr, mount, key name and namespace: %s", line)
	}
}
