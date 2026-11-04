package pluginsdk

import (
	"errors"
	"fmt"
	"regexp"

	"gopkg.in/yaml.v3"
)

// Plugin kinds a manifest may declare.
const (
	KindSource = "source"
	KindAction = "action"
	KindFilter = "filter"
)

// SecretHeader is one credential injection rule of the egress proxy.
type SecretHeader struct {
	Host   string `yaml:"host" json:"host"`
	Header string `yaml:"header" json:"header"`
	Ref    string `yaml:"ref" json:"ref"`
	Prefix string `yaml:"prefix" json:"prefix,omitempty"`
}

// Permissions are what the runner grants the plugin: nothing else is reachable.
type Permissions struct {
	// EgressHosts are the only hosts the plugin may call (through the runner's egress proxy).
	EgressHosts []string `yaml:"egress_hosts" json:"egress_hosts"`
	// SecretRefs name the secrets the egress proxy may inject; the plugin never sees values.
	SecretRefs []string `yaml:"secret_refs" json:"secret_refs"`
	// SecretHeaders say where the egress proxy puts a secret: Header = Prefix + secret(Ref) on
	// requests to Host. Ref must be in SecretRefs and Host in EgressHosts.
	SecretHeaders []SecretHeader `yaml:"secret_headers" json:"secret_headers"`
	MaxCPUMs      int            `yaml:"max_cpu_ms" json:"max_cpu_ms"`
	MaxMemMB      int            `yaml:"max_mem_mb" json:"max_mem_mb"`
}

// Manifest is plugin.yaml.
type Manifest struct {
	Name         string         `yaml:"name" json:"name"`
	Version      string         `yaml:"version" json:"version"`
	Kinds        []string       `yaml:"kinds" json:"kinds"`
	ConfigSchema map[string]any `yaml:"config_schema" json:"config_schema,omitempty"`
	Permissions  Permissions    `yaml:"permissions" json:"permissions"`
}

var nameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)

// Defaults for the resource limits when the manifest leaves them 0.
const (
	DefaultCPUMs = 1000
	DefaultMemMB = 256
	MaxMemMB     = 2048
)

// ParseManifest decodes and validates plugin.yaml.
func ParseManifest(b []byte) (Manifest, error) {
	var m Manifest
	if err := yaml.Unmarshal(b, &m); err != nil {
		return m, fmt.Errorf("plugin.yaml: %w", err)
	}
	return m, m.Validate()
}

// Validate checks names, kinds and limits, and fills the limit defaults.
func (m *Manifest) Validate() error {
	if !nameRE.MatchString(m.Name) {
		return errors.New("name must be a-z, 0-9, '_' or '-', max 64")
	}
	if m.Version == "" || len(m.Version) > 64 {
		return errors.New("version must be 1 to 64 characters")
	}
	if len(m.Kinds) == 0 {
		return errors.New("kinds must list source, action and/or filter")
	}
	for _, k := range m.Kinds {
		if k != KindSource && k != KindAction && k != KindFilter {
			return fmt.Errorf("unknown kind %q", k)
		}
	}
	if m.Permissions.MaxCPUMs == 0 {
		m.Permissions.MaxCPUMs = DefaultCPUMs
	}
	if m.Permissions.MaxMemMB == 0 {
		m.Permissions.MaxMemMB = DefaultMemMB
	}
	if m.Permissions.MaxCPUMs < 0 || m.Permissions.MaxMemMB < 0 || m.Permissions.MaxMemMB > MaxMemMB {
		return fmt.Errorf("max_cpu_ms must be positive and max_mem_mb 1 to %d", MaxMemMB)
	}
	return nil
}

// Has reports whether the manifest declares the kind.
func (m Manifest) Has(kind string) bool {
	for _, k := range m.Kinds {
		if k == kind {
			return true
		}
	}
	return false
}
