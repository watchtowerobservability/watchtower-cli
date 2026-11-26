package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// No test may touch the developer's real keychain.
func TestMain(m *testing.M) {
	keychainOS = "none"
	os.Exit(m.Run())
}

type ranCmd struct {
	name, stdin string
	env, args   []string
}

func fakeKeychain(t *testing.T, goos string, reply string, fail bool) *[]ranCmd {
	t.Helper()
	var ran []ranCmd
	oldRun, oldOS, oldFind := keychainRun, keychainOS, keychainFind
	keychainOS = goos
	keychainFind = func(string) (string, error) { return "/usr/bin/secret-tool", nil }
	keychainRun = func(_ context.Context, name, stdin string, env []string, args ...string) (string, error) {
		ran = append(ran, ranCmd{name, stdin, env, args})
		if fail {
			return "", errors.New(name + " failed")
		}
		return reply, nil
	}
	t.Cleanup(func() { keychainRun, keychainOS, keychainFind = oldRun, oldOS, oldFind })
	return &ran
}

func TestKeychainKeepsTheSecretOutOfArgv(t *testing.T) {
	const secret = "wtu_abcdefghijklmnop"
	for _, goos := range []string{"darwin", "linux", "windows"} {
		ran := fakeKeychain(t, goos, "", false)
		if err := keychainSet(context.Background(), "default", secret); err != nil {
			t.Fatalf("%s: %v", goos, err)
		}
		if len(*ran) != 1 {
			t.Fatalf("%s: ran %v", goos, *ran)
		}
		r := (*ran)[0]
		if strings.Contains(strings.Join(r.args, " "), secret) {
			t.Fatalf("%s: the secret is in argv: %v", goos, r.args)
		}
		inStdin, inEnv := strings.Contains(r.stdin, secret), strings.Contains(strings.Join(r.env, " "), secret)
		if !inStdin && !inEnv {
			t.Fatalf("%s: the secret reached the tool by neither stdin nor the environment: %+v", goos, r)
		}
	}
}

func TestKeychainGetAndNoSecretShapes(t *testing.T) {
	fakeKeychain(t, "darwin", "wtu_abcdefghijklmnop\n", false)
	if k, err := keychainGet(context.Background(), "default"); err != nil || k != "wtu_abcdefghijklmnop" {
		t.Fatalf("get = %q %v", k, err)
	}
	for _, bad := range []string{"short", "has space in it 12345", `quote"d_token_123456`} {
		if err := keychainSet(context.Background(), "default", bad); err == nil {
			t.Fatalf("%q must not reach a keychain tool", bad)
		}
	}
	if err := keychainSet(context.Background(), "my ctx", "wtu_abcdefghijklmnop"); err == nil {
		t.Fatal("a context name with a space must not reach the keychain tool")
	}
}

// Login keeps the token out of the config file when a keychain takes it, and falls back to the file
// with a note (never printing the token) when it does not.
func TestLoginStoresInKeychainOrFallsBackToTheFile(t *testing.T) {
	const secret = "wtk_abcdefghijklmnopqrst"
	for _, tc := range []struct {
		name string
		fail bool
	}{{"keychain", false}, {"fallback", true}} {
		t.Run(tc.name, func(t *testing.T) {
			ran := fakeKeychain(t, "darwin", secret, tc.fail)
			t.Setenv("WTCTL_CONFIG", filepath.Join(t.TempDir(), "config.json"))
			var out bytes.Buffer
			if err := loginMain(context.Background(), []string{"--context", "lh", "--api", "https://wt.example", "--key", secret, "--verify=false", "--project", "linkhub/linkhub"}, &out); err != nil {
				t.Fatal(err)
			}
			cfg, _, err := loadConfig()
			if err != nil {
				t.Fatal(err)
			}
			got := cfg.Contexts["lh"].Key
			if strings.Contains(out.String(), secret) {
				t.Fatalf("login printed the token: %s", out.String())
			}
			if tc.fail {
				if got != secret || !strings.Contains(out.String(), "note: the token could not go to an OS keychain") {
					t.Fatalf("fallback: key=%q out=%s", got, out.String())
				}
				return
			}
			if got != keychainKey || len(*ran) == 0 {
				t.Fatalf("the file must hold only the marker, got %q", got)
			}
			if back, err := contextKey(context.Background(), "lh", cfg.Contexts["lh"]); err != nil || back != secret {
				t.Fatalf("read back %q %v", back, err)
			}
		})
	}
}
