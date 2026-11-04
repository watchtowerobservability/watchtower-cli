package main

import (
	"context"
	"errors"
	"io"
	"strings"
)

const completionUsage = "usage: wtctl completion bash|zsh|fish|powershell"

// topCommands is sorted.
var topCommands = []string{"apply", "checks", "completion", "context", "dashboards", "debug-files", "diff", "export", "gatus", "gen", "login", "logs", "manifest", "pipeline", "profile", "query", "release", "routing", "rules", "self-update", "send-test", "sourcemaps", "spans", "tests", "version"}

// completionMain prints a shell completion script for the top-level commands.
func completionMain(_ context.Context, args []string, out io.Writer) error {
	if len(args) != 1 {
		return errors.New(completionUsage)
	}
	words := strings.Join(topCommands, " ")
	var s string
	switch args[0] {
	case "bash":
		s = "_wtctl() { COMPREPLY=($(compgen -W \"" + words + "\" -- \"${COMP_WORDS[1]}\")); }\ncomplete -F _wtctl wtctl\n"
	case "zsh":
		s = "#compdef wtctl\n_wtctl() { _arguments '1: :(" + words + ")' '*::arg:_files'; }\ncompdef _wtctl wtctl\n"
	case "fish":
		s = "complete -c wtctl -f -n '__fish_use_subcommand' -a '" + words + "'\n"
	case "powershell":
		s = "Register-ArgumentCompleter -Native -CommandName wtctl -ScriptBlock {\n" +
			"  param($word, $ast, $pos)\n  '" + strings.Join(topCommands, "','") + "' | Where-Object { $_ -like \"$word*\" } |\n" +
			"    ForEach-Object { [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', $_) }\n}\n"
	default:
		return errors.New(completionUsage)
	}
	_, err := io.WriteString(out, s)
	return err
}
