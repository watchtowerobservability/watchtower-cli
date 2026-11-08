package main

// More open SAST rules (C7), appended to the base set in scan_rules.go. Same model: one regex per
// line, conservative patterns. The Python f-string rule exists because the gpython taint pass
// cannot parse f-strings (see scan_taint_py.go), so the commonest Python injection shape is
// caught here at line level.
// shortcut: line-level regex, no dataflow; a multi-line statement is missed. Upgrade: feed
// Semgrep/CodeQL SARIF to the same endpoint.

import "regexp"

func init() {
	rules = append(rules, []scanRule{
		{"sast/py-fstring-sql", "SQL built with an f-string or str.format", "8.1", []string{".py"},
			regexp.MustCompile(`(?i)\.(execute|executemany|executescript|raw)\(\s*(f["']|["'][^"']*(select|insert|update|delete)[^"']*["']\s*(%|\.format\())`)},
		{"sast/py-fstring-sql-var", "SQL statement assigned from an f-string", "7.5", []string{".py"},
			regexp.MustCompile(`(?i)=\s*f["']\s*(select|insert\s+into|update|delete\s+from)\b[^"]*\{`)},
		{"sast/py-pickle-load", "Unsafe deserialization (pickle/yaml.load)", "8.1", []string{".py"},
			regexp.MustCompile(`\b(pickle\.loads?|cPickle\.loads?|marshal\.loads?|yaml\.load\()`)},
		{"sast/py-shell-true", "subprocess with shell=True", "7.8", []string{".py"},
			regexp.MustCompile(`shell\s*=\s*True`)},
		{"sast/py-debug-true", "Debug mode enabled", "5.3", []string{".py"},
			regexp.MustCompile(`\b(app\.run\([^)]*debug\s*=\s*True|DEBUG\s*=\s*True)`)},
		{"sast/js-innerhtml", "Assignment to innerHTML / document.write", "6.1", []string{".js", ".ts", ".jsx", ".tsx"},
			regexp.MustCompile(`\.innerHTML\s*=|document\.write(ln)?\(|dangerouslySetInnerHTML`)},
		{"sast/js-new-function", "Function constructor / string timer", "8.1", []string{".js", ".ts", ".jsx", ".tsx"},
			regexp.MustCompile(`new\s+Function\s*\(|set(Timeout|Interval)\(\s*["'` + "`" + `]`)},
		{"sast/js-template-sql", "SQL built in a template literal", "8.1", []string{".js", ".ts"},
			regexp.MustCompile("(?i)`\\s*(select|insert\\s+into|update|delete\\s+from)\\b[^`]*\\$\\{")},
		{"sast/js-tls-off", "TLS verification disabled", "7.4", []string{".js", ".ts", ".py", ".go", ".java"},
			regexp.MustCompile(`(?i)rejectUnauthorized\s*:\s*false|InsecureSkipVerify\s*:\s*true|verify\s*=\s*False|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*["']?0`)},
		{"sast/path-traversal-join", "File path joined from request input", "7.5", []string{".js", ".ts", ".py", ".go"},
			regexp.MustCompile(`(?i)(readFile(Sync)?|createReadStream|open|os\.Open|ioutil\.ReadFile|os\.ReadFile)\([^)]*(req\.|request\.|r\.URL|r\.FormValue|params)`)},
		{"sast/open-redirect", "Redirect to a request-controlled URL", "6.1", []string{".js", ".ts", ".py", ".go"},
			regexp.MustCompile(`(?i)(res\.redirect|redirect|http\.Redirect)\([^)]*(req\.(query|params|body)|request\.(args|GET|POST|values)|r\.URL\.Query|r\.FormValue)`)},
		{"sast/java-sql-concat", "JDBC statement built by concatenation", "8.1", []string{".java", ".kt"},
			regexp.MustCompile(`(?i)(createStatement\(\)|executeQuery|executeUpdate|prepareStatement)\(\s*"[^"]*"\s*\+`)},
		{"sast/java-deserialization", "Java native deserialization", "8.1", []string{".java", ".kt"},
			regexp.MustCompile(`new\s+ObjectInputStream\s*\(|XMLDecoder\s*\(`)},
		{"sast/java-xxe", "XML parser without secure-processing", "7.5", []string{".java", ".kt"},
			regexp.MustCompile(`DocumentBuilderFactory\.newInstance\(\)|SAXParserFactory\.newInstance\(\)|XMLInputFactory\.newInstance\(\)`)},
		{"sast/go-sql-sprintf", "SQL built with fmt.Sprintf", "8.1", []string{".go"},
			regexp.MustCompile(`(?i)fmt\.Sprintf\(\s*"[^"]*\b(select|insert\s+into|update|delete\s+from)\b[^"]*%[sv]`)},
		{"sast/go-weak-tls", "TLS minimum version below 1.2", "5.9", []string{".go"},
			regexp.MustCompile(`MinVersion:\s*tls\.VersionTLS1[01]\b|MinVersion:\s*tls\.VersionSSL30`)},
		{"sast/rb-system-interp", "Shell command with interpolation", "9.1", []string{".rb"},
			regexp.MustCompile("(system|exec|%x|`)\\s*\\(?[^\\n]*#\\{")},
		{"sast/php-include-var", "include/require of a variable", "8.8", []string{".php"},
			regexp.MustCompile(`(?i)\b(include|require)(_once)?\s*\(?\s*\$_(GET|POST|REQUEST)`)},
		{"sast/private-key", "Private key committed", "9.0", nil,
			regexp.MustCompile(`-----BEGIN (RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----`)},
		{"sast/aws-access-key", "AWS access key id", "8.0", nil,
			regexp.MustCompile(`\b(AKIA|ASIA)[0-9A-Z]{16}\b`)},
		{"sast/jwt-none", "JWT accepted with alg none", "8.1", []string{".js", ".ts", ".py", ".java"},
			regexp.MustCompile(`(?i)algorithms?\s*[:=]\s*\[?\s*["']none["']|verify\s*=\s*False.*jwt|jwt.*verify_signature["']?\s*:\s*False`)},
	}...)
}
