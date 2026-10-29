package main

// instrumentFile is one file the instrument command writes into the repository.
type instrumentFile struct{ Path, Content string }

// instrumentation is the OpenTelemetry setup for one language: files to write and the commands the
// developer runs afterwards (the command never runs them). No template holds an endpoint or a key:
// both come from the environment (WT_ENDPOINT, WT_INGEST_KEY), so nothing secret is committed.
type instrumentation struct {
	Lang  string
	Files []instrumentFile
	Next  []string
}

// langMarkers maps a repository file name to its language, first match wins.
var langMarkers = []struct{ File, Lang string }{
	{"go.mod", "go"}, {"package.json", "node"}, {"pyproject.toml", "python"}, {"requirements.txt", "python"},
	{"setup.py", "python"}, {"pom.xml", "java"}, {"build.gradle", "java"}, {"build.gradle.kts", "java"},
	{"Gemfile", "ruby"}, {"composer.json", "php"}, {"Cargo.toml", "rust"},
}

// instrumentTemplates is keyed by language. Each setup uses the Watchtower SDK of that language,
// which is a thin layer over the OpenTelemetry SDK (OTLP export, offline buffer, redaction hook).
var instrumentTemplates = map[string]instrumentation{
	"go": {Lang: "go", Files: []instrumentFile{{"internal/watchtower/otel.go", `// Package watchtower starts OpenTelemetry export to Watchtower. Call Start once from main.
package watchtower

import (
	"context"
	"os"

	"watchtower/sdk/wtotel"
)

// Start returns the shutdown function; call it before the process exits.
func Start(ctx context.Context, service string) (func(context.Context) error, error) {
	return wtotel.Init(ctx, wtotel.Options{
		Endpoint:    os.Getenv("WT_ENDPOINT"),
		IngestKey:   os.Getenv("WT_INGEST_KEY"),
		ServiceName: service,
		BufferDir:   os.Getenv("WT_BUFFER_DIR"),
	})
}
`}}, Next: []string{"go get watchtower/sdk/wtotel", "call watchtower.Start(ctx, \"<service>\") at the top of main and defer the shutdown"}},
	"node": {Lang: "node", Files: []instrumentFile{{"watchtower-otel.js", `// Load first: node --require ./watchtower-otel.js app.js
const wt = require('@watchtowerobservability/node');
wt.init({ apiKey: process.env.WT_INGEST_KEY, project: process.env.WT_PROJECT_ID, bufferDir: '.wt-buffer' });
`}}, Next: []string{"npm install @watchtowerobservability/node", "start the app with: node --require ./watchtower-otel.js <entry>"}},
	"python": {Lang: "python", Files: []instrumentFile{{"watchtower_otel.py", `"""Import this module first (or call setup() at startup)."""
import os

import watchtower


def setup() -> None:
    watchtower.init(os.environ["WT_INGEST_KEY"], project=os.environ.get("WT_PROJECT_ID"), buffer_dir=".wt-buffer")


setup()
`}}, Next: []string{"pip install watchtower-sdk", "add `import watchtower_otel` as the first import of the entry module"}},
	"java": {Lang: "java", Files: []instrumentFile{{"src/main/java/WatchtowerOtel.java", `import io.watchtower.Watchtower;

/** Call WatchtowerOtel.start("service") first in main. Endpoint and key come from the environment. */
public final class WatchtowerOtel {
  private WatchtowerOtel() {}

  public static void start(String service) {
    Watchtower.init(new Watchtower.Options()
        .apiKey(System.getenv("WT_INGEST_KEY"))
        .endpoint(System.getenv("WT_OTLP_ENDPOINT"))
        .serviceName(service));
  }
}
`}}, Next: []string{"add io.watchtower:watchtower-sdk to the build", "call WatchtowerOtel.start(\"<service>\") first in main"}},
	"ruby": {Lang: "ruby", Files: []instrumentFile{{"config/initializers/watchtower_otel.rb", `require 'watchtower'

Watchtower.init(Watchtower::Config.new(service: ENV.fetch('WT_SERVICE', 'app'), endpoint: ENV['WT_ENDPOINT'], key: ENV['WT_INGEST_KEY']))
`}}, Next: []string{"bundle add watchtower-sdk"}},
	"php": {Lang: "php", Files: []instrumentFile{{"watchtower_otel.php", `<?php
declare(strict_types=1);

// require this file first from your entry point.
require_once __DIR__ . '/vendor/autoload.php';

\Watchtower\Watchtower::init(\Watchtower\Config::fromEnv(getenv('WT_SERVICE') ?: 'app'));
`}}, Next: []string{"composer require watchtower/sdk"}},
	"rust": {Lang: "rust", Files: []instrumentFile{{"src/watchtower_otel.rs", `//! Reads WT_ENDPOINT and WT_INGEST_KEY. Call start() first in main and keep the returned provider alive until exit.
pub fn start(service: &str) -> Result<watchtower_sdk::SdkTracerProvider, Box<dyn std::error::Error>> {
    Ok(watchtower_sdk::init(&watchtower_sdk::Config::from_env(service))?)
}
`}}, Next: []string{"cargo add watchtower-sdk", "add `mod watchtower_otel;` and call watchtower_otel::start(\"<service>\") first in main"}},
	"dotnet": {Lang: "dotnet", Files: []instrumentFile{{"WatchtowerOtel.cs", `using Watchtower;

public static class WatchtowerOtel
{
    // Keep the provider for the life of the process.
    public static OpenTelemetry.Trace.TracerProvider Start(string service) =>
        Watchtower.Watchtower.Init(new Config(service, Environment.GetEnvironmentVariable("WT_ENDPOINT"), Environment.GetEnvironmentVariable("WT_INGEST_KEY")));
}
`}}, Next: []string{"dotnet add package Watchtower.Sdk", "call WatchtowerOtel.Start(\"<service>\") first in Program.cs"}},
}
