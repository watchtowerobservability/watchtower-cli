// Command wtctl is the Watchtower operator CLI.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/watchtowerobservability/watchtower-cli/internal/genreplay"
)

func main() {
	args, err := applyContext(os.Args[1:]) // --context / $WT_CONTEXT / current context (contexts.go)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	os.Args = append(os.Args[:1], args...)
	if len(os.Args) >= 3 && os.Args[1] == "release" && os.Args[2] == "gate" {
		// --wait can outlast the 60 s of the other release commands; the flag bounds it.
		code, err := gateMain(context.Background(), os.Args[3:], os.Stdout)
		if helpExit(err, os.Args[3:]) {
			return
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, "release gate failed:", err)
		}
		os.Exit(code)
	}
	if len(os.Args) >= 2 && os.Args[1] == "release" {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		if err := releaseMain(ctx, os.Args[2:], os.Stdout); err != nil && !helpExit(err, os.Args[2:]) {
			fmt.Fprintln(os.Stderr, "release failed:", err)
			os.Exit(1)
		}
		return
	}
	if len(os.Args) >= 2 && os.Args[1] == "lsp" {
		if err := lspMain(context.Background()); err != nil {
			fmt.Fprintln(os.Stderr, "lsp failed:", err)
			os.Exit(1)
		}
		return
	}
	for name, run := range map[string]func(context.Context, []string, io.Writer) error{
		"sourcemaps":   sourcemapsMain,
		"debug-files":  debugFilesMain,
		"profile":      profileMain,
		"size":         sizeMain,
		"checks":       checksMain,
		"scan":         scanMain,
		"deps":         depsMain,
		"test":         testMain,
		"ci":           ciMain,
		"rules":        rulesMain,
		"routing":      routingMain,
		"security":     securityMain,
		"gatus":        gatusMain,
		"gen":          func(ctx context.Context, a []string, o io.Writer) error { return genreplay.Main(ctx, a, o, nil) },
		"apply":        applyMain,
		"import":       importMain,
		"migrate":      migrateMain,
		"shadow":       shadowMain,
		"diff":         diffMain,
		"export":       exportMain,
		"completion":   completionMain,
		"datasets":     datasetsMain,
		"mcp":          mcpMain,
		"instrument":   instrumentMain,
		"dashboards":   dashboardsMain,
		"pipeline":     pipelineMain,
		"kafka":        kafkaMain,
		"backup":       backupMain,
		"archive":      archiveMain,
		"restore":      restoreMain,
		"fleet":        fleetMain,
		"upgrade":      upgradeMain,
		"license":      licenseMain,
		"admin":        adminMain,
		"org":          orgMain,
		"loadtest":     loadtestMain,
		"evals":        evalsMain,
		"prompts":      promptsMain,
		"manifest":     manifestMain,
		"self-monitor": selfMonitorMain,
		"internal":     internalMain,
		"bundle":       bundleMain,
		"agent":        agentMain,
		"k8s":          k8sMain,
		"activity":     activityMain,
		"metrics":      metricsMain,
		"plugin":       pluginMain,
		"integration":  integrationMain,
		"ch":           chMain,
		"mib":          mibMain,
		"login":        loginMain,
		"logout":       logoutMain,
		"provision":    provisionMain,
		"context":      contextMain,
		"query":        queryMain,
		"logs":         logsMain,
		"spans":        spansMain,
		"self-update":  selfUpdateMain,
		"tests":        testsMain,
		"doctor":       doctorMain,
		"env":          envMain,
		"version":      versionMain,
		"--version":    versionMain,
	} {
		if len(os.Args) >= 2 && os.Args[1] == name {
			limit := 30 * time.Minute
			if name == "gen" || name == "mcp" || name == "logs" {
				limit = 24 * time.Hour // --duration governs
			}
			if name == "tests" {
				limit = 6 * time.Hour // `tests coverage go` runs every package's tests
			}
			ctx, cancel := context.WithTimeout(context.Background(), limit)
			defer cancel()
			if err := run(ctx, os.Args[2:], os.Stdout); err != nil && !helpExit(err, os.Args[2:]) {
				var ec exitCode
				if errors.As(err, &ec) {
					os.Exit(int(ec)) // `checks run` reports its own exit code (0, 1 or 2)
				}
				fmt.Fprintln(os.Stderr, name+" failed:", err)
				os.Exit(1)
			}
			return
		}
	}
	if len(os.Args) < 2 || os.Args[1] != "send-test" {
		fmt.Fprintln(os.Stderr, "usage: wtctl send-test --endpoint <url> --key <wti_...> [--protocol grpc|http]")
		fmt.Fprintln(os.Stderr, "       wtctl sourcemaps upload <dir> --api <url> --key <key> --project <id> [--release <version>]")
		fmt.Fprintln(os.Stderr, "       wtctl debug-files upload <path>... --api <url> --key <key> --project <id> [--release <version>]")
		fmt.Fprintln(os.Stderr, "       "+profileUsage[len("usage: "):])
		fmt.Fprintln(os.Stderr, "       wtctl checks run--api <url> --key <key> --project <id> [--tag ci] [--wait] [--timeout 5m] [--junit out.xml]")
		fmt.Fprintln(os.Stderr, "       "+ciUsage[len("usage: "):])
		fmt.Fprintln(os.Stderr, "       "+ciJunitUsage[len("usage: "):])
		fmt.Fprintln(os.Stderr, "       "+ciPlanUsage[len("usage: "):])
		fmt.Fprintln(os.Stderr, "       wtctl checks import-playwright <file.spec.ts>")
		fmt.Fprintln(os.Stderr, "       wtctl checks record-mobile --device <preset>|list [--app <build>] [--appium <url>]")
		fmt.Fprintln(os.Stderr, "       wtctl checks import-postman <collection.json>")
		fmt.Fprintln(os.Stderr, "       wtctl checks import-curl '<curl command>' | <file> | -")
		fmt.Fprintln(os.Stderr, "       "+checksWatchUsage[len("usage: "):])
		fmt.Fprintln(os.Stderr, "       wtctl rules import <rules.yaml> --api <url> --key <key> --project <id>")
		fmt.Fprintln(os.Stderr, "       wtctl routing import-alertmanager <alertmanager.yaml> --api <url> --key <key> --project <id> [--apply]")
		fmt.Fprintln(os.Stderr, "       wtctl release create <version> --api <url> --key <key> --project <id> [--commits auto|<range>] [--deploy <env>]")
		fmt.Fprintln(os.Stderr, "       wtctl release gate <version> --api <url> --key <key> --project <id> [--wait] [--timeout 30m]   (exit 0 pass, 1 fail, 2 timeout or insufficient data)")
		fmt.Fprintln(os.Stderr, "       "+genreplay.GenUsage[len("usage: "):])
		fmt.Fprintln(os.Stderr, "       "+strings.ReplaceAll(asCodeUsage[len("usage: "):], "\n       ", "\n       "))
		fmt.Fprintln(os.Stderr, "       "+importUsage[len("usage: "):])
		fmt.Fprintln(os.Stderr, "       "+migrateUsage[len("usage: "):])
		fmt.Fprintln(os.Stderr, "       "+shadowUsage[len("usage: "):])
		fmt.Fprintln(os.Stderr, "       "+completionUsage[len("usage: "):])
		fmt.Fprintln(os.Stderr, "       "+strings.ReplaceAll(datasetsUsage[len("usage: "):], "\n       ", "\n       "))
		fmt.Fprintln(os.Stderr, "       "+strings.ReplaceAll(evalsUsage[len("usage: "):], "\n", "\n       "))
		fmt.Fprintln(os.Stderr, "       "+promptsUsage[len("usage: "):])
		fmt.Fprintln(os.Stderr, "       "+strings.ReplaceAll(mcpUsage[len("usage: "):], "\n       ", "\n       "))
		fmt.Fprintln(os.Stderr, "       "+strings.ReplaceAll(instrumentUsage[len("usage: "):], "\n       ", "\n       "))
		fmt.Fprintln(os.Stderr, "       "+strings.ReplaceAll(dashboardsUsage[len("usage: "):], "\n       ", "\n       "))
		fmt.Fprintln(os.Stderr, "       "+kafkaUsage[len("usage: "):])
		fmt.Fprintln(os.Stderr, "       "+backupUsage[len("usage: "):])
		fmt.Fprintln(os.Stderr, "       "+archiveUsage[len("usage: "):])
		fmt.Fprintln(os.Stderr, "       "+strings.ReplaceAll(pluginUsage[len("usage: "):], "\n       ", "\n       "))
		fmt.Fprintln(os.Stderr, "       "+restoreUsage[len("usage: "):])
		fmt.Fprintln(os.Stderr, "       "+chTuneUsage[len("usage: "):])
		fmt.Fprintln(os.Stderr, "       "+strings.ReplaceAll(queryUsage[len("usage: "):], "\n       ", "\n       "))
		fmt.Fprintln(os.Stderr, "       "+strings.ReplaceAll(contextUsage[len("usage: "):], "\n       ", "\n       "))
		fmt.Fprintln(os.Stderr, "       "+strings.ReplaceAll(spansUsage[len("usage: "):], "\n       ", "\n       "))
		fmt.Fprintln(os.Stderr, "       "+selfUpdateUsage[len("usage: "):])
		fmt.Fprintln(os.Stderr, "       "+strings.ReplaceAll(testsUsage[len("usage: "):], "\n       ", "\n       "))
		fmt.Fprintln(os.Stderr, "       "+versionUsage[len("usage: "):])
		fmt.Fprintln(os.Stderr, "       "+provisionUsage[len("usage: "):])
		fmt.Fprintln(os.Stderr, "       wtctl gatus config --api <url> --key <key> --project <slug> --project-id <prj_...> [--env <e>]")
		os.Exit(2)
	}
	fs := flag.NewFlagSet("send-test", flag.ExitOnError)
	endpoint := fs.String("endpoint", "", "OTLP endpoint, e.g. http://localhost:4318")
	key := fs.String("key", "", "ingestion key (wti_...)")
	proto := fs.String("protocol", "http", "grpc or http")
	_ = fs.Parse(os.Args[2:])
	if *endpoint == "" || *key == "" {
		fs.Usage()
		os.Exit(2)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := sendTest(ctx, *endpoint, *key, *proto, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "send-test failed:", err)
		os.Exit(1)
	}
}

// helpExit reports whether a command failed only because -h/--help was asked for: the flag
// package has printed the usage, so the exit is 0, not a failure.
func helpExit(err error, args []string) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, flag.ErrHelp) {
		return true
	}
	for _, a := range args {
		switch a {
		case "--":
			return false
		case "-h", "--h", "-help", "--help":
			return true
		}
	}
	return false
}
