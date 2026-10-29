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
	if len(os.Args) >= 3 && os.Args[1] == "release" && os.Args[2] == "gate" {
		// --wait can outlast the 60 s of the other release commands; the flag bounds it.
		code, err := gateMain(context.Background(), os.Args[3:], os.Stdout)
		if err != nil {
			fmt.Fprintln(os.Stderr, "release gate failed:", err)
		}
		os.Exit(code)
	}
	if len(os.Args) >= 2 && os.Args[1] == "release" {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		if err := releaseMain(ctx, os.Args[2:], os.Stdout); err != nil {
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
		"checks":       checksMain,
		"test":         testMain,
		"ci":           ciMain,
		"rules":        rulesMain,
		"routing":      routingMain,
		"gatus":        gatusMain,
		"gen":          func(ctx context.Context, a []string, o io.Writer) error { return genreplay.Main(ctx, a, o, nil) },
		"apply":        applyMain,
		"import":       importMain,
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
		"restore":      restoreMain,
		"fleet":        fleetMain,
		"upgrade":      upgradeMain,
		"license":      licenseMain,
		"admin":        adminMain,
		"org":          orgMain,
		"evals":        evalsMain,
		"prompts":      promptsMain,
		"manifest":     manifestMain,
		"self-monitor": selfMonitorMain,
		"internal":     internalMain,
		"bundle":       bundleMain,
		"agent":        agentMain,
	} {
		if len(os.Args) >= 2 && os.Args[1] == name {
			limit := 30 * time.Minute
			if name == "gen" || name == "mcp" {
				limit = 24 * time.Hour // --duration governs
			}
			ctx, cancel := context.WithTimeout(context.Background(), limit)
			defer cancel()
			if err := run(ctx, os.Args[2:], os.Stdout); err != nil {
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
		fmt.Fprintln(os.Stderr, "       wtctl checks import-playwright <file.spec.ts>")
		fmt.Fprintln(os.Stderr, "       "+checksWatchUsage[len("usage: "):])
		fmt.Fprintln(os.Stderr, "       wtctl rules import <rules.yaml> --api <url> --key <key> --project <id>")
		fmt.Fprintln(os.Stderr, "       wtctl routing import-alertmanager <alertmanager.yaml> --api <url> --key <key> --project <id> [--apply]")
		fmt.Fprintln(os.Stderr, "       wtctl release create <version> --api <url> --key <key> --project <id> [--commits auto|<range>] [--deploy <env>]")
		fmt.Fprintln(os.Stderr, "       wtctl release gate <version> --api <url> --key <key> --project <id> [--wait] [--timeout 30m]   (exit 0 pass, 1 fail, 2 timeout or insufficient data)")
		fmt.Fprintln(os.Stderr, "       "+genreplay.GenUsage[len("usage: "):])
		fmt.Fprintln(os.Stderr, "       "+strings.ReplaceAll(asCodeUsage[len("usage: "):], "\n       ", "\n       "))
		fmt.Fprintln(os.Stderr, "       "+importUsage[len("usage: "):])
		fmt.Fprintln(os.Stderr, "       "+completionUsage[len("usage: "):])
		fmt.Fprintln(os.Stderr, "       "+strings.ReplaceAll(datasetsUsage[len("usage: "):], "\n       ", "\n       "))
		fmt.Fprintln(os.Stderr, "       "+strings.ReplaceAll(evalsUsage[len("usage: "):], "\n", "\n       "))
		fmt.Fprintln(os.Stderr, "       "+promptsUsage[len("usage: "):])
		fmt.Fprintln(os.Stderr, "       "+strings.ReplaceAll(mcpUsage[len("usage: "):], "\n       ", "\n       "))
		fmt.Fprintln(os.Stderr, "       "+strings.ReplaceAll(instrumentUsage[len("usage: "):], "\n       ", "\n       "))
		fmt.Fprintln(os.Stderr, "       "+strings.ReplaceAll(dashboardsUsage[len("usage: "):], "\n       ", "\n       "))
		fmt.Fprintln(os.Stderr, "       "+kafkaUsage[len("usage: "):])
		fmt.Fprintln(os.Stderr, "       "+backupUsage[len("usage: "):])
		fmt.Fprintln(os.Stderr, "       "+restoreUsage[len("usage: "):])
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
