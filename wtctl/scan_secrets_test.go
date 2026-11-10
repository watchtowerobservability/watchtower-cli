package main

import (
	"bufio"
	"hash/crc32"
	"strings"
	"testing"
)

// githubToken builds a token whose checksum is right, the way GitHub issues them.
func githubToken(rnd string) string {
	n := crc32.ChecksumIEEE([]byte(rnd))
	enc := make([]byte, 6)
	for i := 5; i >= 0; i-- {
		enc[i] = base62[n%62]
		n /= 62
	}
	return "ghp_" + rnd + string(enc)
}

func ids(rs []sarifResult) map[string]int {
	m := map[string]int{}
	for _, r := range rs {
		m[r.RuleID] = r.Locations[0].Physical.Region.StartLine
	}
	return m
}

func TestGitHubTokenNeedsItsChecksum(t *testing.T) {
	good := githubToken("a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5")
	bad := good[:len(good)-1] + "0"
	if bad == good {
		bad = good[:len(good)-1] + "1"
	}
	got := ids(scanSecrets("ci.yml", "token: "+good+"\nother: "+bad+"\n"))
	if got["secret/github-token"] != 1 {
		t.Fatalf("the valid token on line 1 must be found, and the bad checksum on line 2 must not: %v", got)
	}
}

func TestEntropyAndPlaceholdersDecideGenericSecrets(t *testing.T) {
	src := "API_TOKEN = \"q8Zr3vLx9TmP2wKdY7bNc4HfJs6GaE1u\"\n" + // random
		"api_key = \"your-api-key-goes-here-please-1234\"\n" + // placeholder
		"password = \"aaaaaaaaaaaaaaaaaaaaaaaa\"\n" // low entropy
	got := ids(scanSecrets("settings.py", src))
	if got["secret/high-entropy"] != 1 || len(got) != 1 {
		t.Fatalf("only the random value counts: %v", got)
	}
}

func TestConfigFilesAreScannedButLockfilesAreNot(t *testing.T) {
	line := "stripe: sk_live_" + strings.Repeat("aB3dE5gH7jK9mN1pQ3sT5vW7", 1) + "\n"
	if len(scanSecrets("deploy/values.yaml", line)) != 1 {
		t.Fatal("a yaml file must be scanned for secrets")
	}
	if len(scanSecrets("package-lock.json", line)) != 0 {
		t.Fatal("a lockfile must not be scanned")
	}
	if len(scanSecrets(".env.production", line)) != 1 {
		t.Fatal(".env files must be scanned")
	}
}

func TestHistoryFindsASecretAddedThenRemoved(t *testing.T) {
	tok := githubToken("a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5")
	patch := "\x00deadbeefcafef00d\n" +
		"diff --git a/app.env b/app.env\n--- a/app.env\n+++ b/app.env\n@@ -0,0 +4,2 @@\n+HOST=x\n+TOKEN=" + tok + "\n" +
		"\x000123456789abcdef\n" +
		"diff --git a/app.env b/app.env\n--- a/app.env\n+++ /dev/null\n@@ -4,2 +0,0 @@\n-TOKEN=" + tok + "\n"
	res := historyScan(bufioScanner(patch))
	if len(res) != 1 {
		t.Fatalf("one finding for the commit that added it: %+v", res)
	}
	r := res[0]
	if r.RuleID != "secret/github-token" || r.Locations[0].Physical.Region.StartLine != 5 ||
		!strings.Contains(r.Message.Text, "deadbeef") || strings.Contains(r.Message.Text, tok) {
		t.Fatalf("unexpected result: %+v", r)
	}
}

func bufioScanner(s string) *bufio.Scanner { return bufio.NewScanner(strings.NewReader(s)) }
