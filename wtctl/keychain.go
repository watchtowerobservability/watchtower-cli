package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strings"
	"time"
)

// `wtctl login` keeps the token in the OS keychain when there is one, so no plain-text file holds a
// personal access token: macOS `security`, Linux `secret-tool` (libsecret) when installed, Windows
// the Credential Locker through PowerShell. The secret travels over stdin or the environment, never
// argv, and is never printed. Without a keychain the 0600 context file keeps it, with a printed note.

const keychainService = "wtctl"

// keychainKey is the context field value that says "the token is in the keychain".
const keychainKey = "keychain"

// tokenShape is what a token looks like; anything else is never handed to a shell-ish tool.
var (
	tokenShape = regexp.MustCompile(`^[A-Za-z0-9._~+/=-]{8,512}$`)
	nameShape  = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)
)

// keychainRun runs one tool with stdin and extra environment; a variable so tests can fake the OS.
var keychainRun = func(ctx context.Context, name string, stdin string, env []string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdin = strings.NewReader(stdin)
	cmd.Env = append(os.Environ(), env...)
	var out bytes.Buffer
	cmd.Stdout = &out // stderr is dropped: it must never reach the log
	if err := cmd.Run(); err != nil {
		return "", errors.New(name + " failed")
	}
	return out.String(), nil
}

var (
	keychainOS   = runtime.GOOS
	keychainFind = exec.LookPath
)

// errNoKeychain means this machine has no keychain tool (the caller falls back to the file).
var errNoKeychain = errors.New("no OS keychain tool found")

const psVault = `[void][Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime];` +
	`$v=New-Object Windows.Security.Credentials.PasswordVault;`

// keychainSet stores secret for the context name.
func keychainSet(ctx context.Context, name, secret string) error {
	if os.Getenv("WTCTL_KEYCHAIN") == "off" { // CI and containers: keep the 0600 file
		return errNoKeychain
	}
	if !tokenShape.MatchString(secret) || !nameShape.MatchString(name) {
		return errors.New("the token or the context name has an unexpected shape")
	}
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	switch keychainOS {
	case "darwin":
		// `security -i` reads its commands from stdin, which keeps the secret out of argv.
		_, err := keychainRun(ctx, "security", fmt.Sprintf("add-generic-password -U -s %s -a %q -w %q\n", keychainService, name, secret), nil, "-i")
		return err
	case "linux":
		if _, err := keychainFind("secret-tool"); err != nil {
			return errNoKeychain
		}
		_, err := keychainRun(ctx, "secret-tool", secret, nil, "store", "--label=wtctl "+name, "service", keychainService, "account", name)
		return err
	case "windows":
		script := psVault + `$v.Add((New-Object Windows.Security.Credentials.PasswordCredential('wtctl',$env:WTCTL_NAME,$env:WTCTL_SECRET)))`
		_, err := keychainRun(ctx, "powershell", "", []string{"WTCTL_NAME=" + name, "WTCTL_SECRET=" + secret}, "-NoProfile", "-NonInteractive", "-Command", script)
		return err
	}
	return errNoKeychain
}

// keychainGet reads the secret of the context name.
func keychainGet(ctx context.Context, name string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	var out string
	var err error
	switch keychainOS {
	case "darwin":
		out, err = keychainRun(ctx, "security", "", nil, "find-generic-password", "-s", keychainService, "-a", name, "-w")
	case "linux":
		if _, e := keychainFind("secret-tool"); e != nil {
			return "", errNoKeychain
		}
		out, err = keychainRun(ctx, "secret-tool", "", nil, "lookup", "service", keychainService, "account", name)
	case "windows":
		script := psVault + `$c=$v.Retrieve('wtctl',$env:WTCTL_NAME);$c.RetrievePassword();[Console]::Out.Write($c.Password)`
		out, err = keychainRun(ctx, "powershell", "", []string{"WTCTL_NAME=" + name}, "-NoProfile", "-NonInteractive", "-Command", script)
	default:
		return "", errNoKeychain
	}
	if err != nil {
		return "", err
	}
	if out = strings.TrimSpace(out); out == "" {
		return "", errors.New("the keychain has no token for this context")
	}
	return out, nil
}

// keychainDelete removes the secret of the context name; a missing one is not an error worth reporting.
func keychainDelete(ctx context.Context, name string) {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	switch keychainOS {
	case "darwin":
		_, _ = keychainRun(ctx, "security", "", nil, "delete-generic-password", "-s", keychainService, "-a", name)
	case "linux":
		if _, err := keychainFind("secret-tool"); err == nil {
			_, _ = keychainRun(ctx, "secret-tool", "", nil, "clear", "service", keychainService, "account", name)
		}
	case "windows":
		script := psVault + `$v.Remove($v.Retrieve('wtctl',$env:WTCTL_NAME))`
		_, _ = keychainRun(ctx, "powershell", "", []string{"WTCTL_NAME=" + name}, "-NoProfile", "-NonInteractive", "-Command", script)
	}
}

// contextKey is the API key of a context: from the file, or from the keychain when the file says so.
func contextKey(ctx context.Context, name string, c wtContext) (string, error) {
	if c.Key != keychainKey {
		return c.Key, nil
	}
	k, err := keychainGet(ctx, name)
	if err != nil {
		return "", fmt.Errorf("the token of context %q is in the OS keychain but could not be read (%w); run `wtctl login --context %s` again", name, err, name)
	}
	return k, nil
}
