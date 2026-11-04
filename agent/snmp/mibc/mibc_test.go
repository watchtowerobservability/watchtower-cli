package mibc

import (
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/watchtowerobservability/watchtower-cli/agent/snmp"
)

const acmeMIB = `
ACME-SWITCH-MIB DEFINITIONS ::= BEGIN
IMPORTS
    MODULE-IDENTITY, OBJECT-TYPE, NOTIFICATION-TYPE, Counter64, Integer32, enterprises
        FROM SNMPv2-SMI
    DisplayString FROM SNMPv2-TC;  -- a comment -- -- and another

acme MODULE-IDENTITY
    LAST-UPDATED "202601010000Z"
    ORGANIZATION "Acme"
    CONTACT-INFO "noc@acme.example"
    DESCRIPTION  "Acme switches. Has { braces } and ::= inside the string."
    REVISION     "202601010000Z"
    DESCRIPTION  "First."
    ::= { enterprises 99999 }

AcmeFanState ::= TEXTUAL-CONVENTION
    STATUS current
    DESCRIPTION "fan state"
    SYNTAX INTEGER { ok(1), failed(2), absent(3) }

acmeObjects OBJECT IDENTIFIER ::= { acme 1 }
acmeTraps   OBJECT IDENTIFIER ::= { acme 2 }

acmeCpuLoad OBJECT-TYPE
    SYNTAX      Integer32 (0..100)
    UNITS       "percent"
    MAX-ACCESS  read-only
    STATUS      current
    DESCRIPTION "CPU load."
    ::= { acmeObjects 1 }

acmeFanTable OBJECT-TYPE
    SYNTAX      SEQUENCE OF AcmeFanEntry
    MAX-ACCESS  not-accessible
    STATUS      current
    DESCRIPTION "Fans."
    ::= { acmeObjects 2 }

acmeFanEntry OBJECT-TYPE
    SYNTAX      AcmeFanEntry
    MAX-ACCESS  not-accessible
    STATUS      current
    DESCRIPTION "A fan."
    INDEX       { acmeFanIndex }
    ::= { acmeFanTable 1 }

AcmeFanEntry ::= SEQUENCE { acmeFanIndex Integer32, acmeFanName DisplayString,
    acmeFanState AcmeFanState, acmeFanErrors Counter64 }

acmeFanIndex OBJECT-TYPE
    SYNTAX Integer32 (1..64)
    MAX-ACCESS not-accessible
    STATUS current
    DESCRIPTION "index"
    ::= { acmeFanEntry 1 }

acmeFanName OBJECT-TYPE
    SYNTAX DisplayString (SIZE (0..32))
    MAX-ACCESS read-only
    STATUS current
    DESCRIPTION "name"
    ::= { acmeFanEntry 2 }

acmeFanState OBJECT-TYPE
    SYNTAX AcmeFanState
    MAX-ACCESS read-only
    STATUS current
    DESCRIPTION "state"
    DEFVAL { ok }
    ::= { acmeFanEntry 3 }

acmeFanErrors OBJECT-TYPE
    SYNTAX Counter64
    MAX-ACCESS read-only
    STATUS current
    DESCRIPTION "errors"
    ::= { acmeFanEntry 4 }

acmeFanFailed NOTIFICATION-TYPE
    OBJECTS { acmeFanName, acmeFanState }
    STATUS current
    DESCRIPTION "A fan failed."
    ::= { acmeTraps 0 1 }

acmeFanRecovered NOTIFICATION-TYPE
    OBJECTS { acmeFanName, acmeFanState }
    STATUS current
    DESCRIPTION "A fan is back."
    ::= { acmeTraps 0 2 }
END
`

const acmeV1 = `
ACME-OLD-MIB DEFINITIONS ::= BEGIN
IMPORTS enterprises FROM RFC1155-SMI TRAP-TYPE FROM RFC-1215;
acmeOld OBJECT IDENTIFIER ::= { enterprises 99998 }
acmeOldUpsOnBattery TRAP-TYPE
    ENTERPRISE acmeOld
    VARIABLES { }
    DESCRIPTION "On battery."
    ::= 5
END
`

func compiled(t *testing.T, src, module string) Result {
	t.Helper()
	mods, err := Parse(src)
	if err != nil {
		t.Fatal(err)
	}
	c := New()
	c.Add(mods...)
	r, err := c.Compile(module)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestCompileTablesScalarsAndTraps(t *testing.T) {
	r := compiled(t, acmeMIB, "ACME-SWITCH-MIB")
	if len(r.Warnings) != 0 {
		t.Fatalf("warnings: %v", r.Warnings)
	}
	m := r.Manifest
	if m.Name != "acme-switch-mib" || len(m.Scalars) != 1 || m.Scalars[0].OID != "1.3.6.1.4.1.99999.1.1.0" ||
		m.Scalars[0].Metric != "snmp.acme_switch.acme_cpu_load" || m.Scalars[0].Unit != "percent" {
		t.Fatalf("scalars %+v", m.Scalars)
	}
	if len(m.Tables) != 1 {
		t.Fatalf("tables %+v", m.Tables)
	}
	tb := m.Tables[0]
	if tb.OID != "1.3.6.1.4.1.99999.1.2.1" || tb.LabelCol != "2" || tb.LabelAttr != "snmp.acme_switch.acme_fan_name" || len(tb.Items) != 2 {
		t.Fatalf("table %+v", tb)
	}
	if tb.Items[0].Col != "3" || tb.Items[0].Kind != "" || tb.Items[1].Col != "4" || tb.Items[1].Kind != "counter" ||
		tb.Items[1].Metric != "snmp.acme_switch.acme_fan_errors.rate" {
		t.Fatalf("items %+v", tb.Items)
	}
	tr := r.Traps.Traps
	if len(tr) != 2 || tr[0].OID != "1.3.6.1.4.1.99999.2.0.1" || tr[0].Severity != "ERROR" || tr[1].Severity != "INFO" {
		t.Fatalf("traps %+v", tr)
	}
	if v := tr[0].Varbinds[1]; v.OID != "1.3.6.1.4.1.99999.1.2.1.3" || v.Enum["2"] != "failed" {
		t.Fatalf("varbind %+v", v)
	}
}

func TestCompiledOutputLoadsAsManifestAndProfile(t *testing.T) {
	r := compiled(t, acmeMIB, "ACME-SWITCH-MIB")
	b, err := yaml.Marshal(r.Manifest)
	if err != nil {
		t.Fatal(err)
	}
	var m snmp.Manifest
	dec := yaml.Unmarshal(b, &m)
	if dec != nil || m.Tables[0].Items[1].Kind != "counter" {
		t.Fatalf("%v %s", dec, b)
	}
	tb, err := yaml.Marshal(r.Traps)
	if err != nil {
		t.Fatal(err)
	}
	var f snmp.TrapProfileFile
	if err := yaml.Unmarshal(tb, &f); err != nil || len(f.Traps) != 2 {
		t.Fatalf("%v %s", err, tb)
	}
}

func TestTrapTypeV1UsesEnterpriseZeroSpecific(t *testing.T) {
	r := compiled(t, acmeV1, "ACME-OLD-MIB")
	if len(r.Traps.Traps) != 1 || r.Traps.Traps[0].OID != "1.3.6.1.4.1.99998.0.5" {
		t.Fatalf("%+v", r.Traps)
	}
}

func TestUnresolvedParentIsAWarningNotAPanic(t *testing.T) {
	src := "X-MIB DEFINITIONS ::= BEGIN\nfoo OBJECT-TYPE SYNTAX Integer32 MAX-ACCESS read-only STATUS current DESCRIPTION \"d\" ::= { missingNode 1 }\nEND\n"
	r := compiled(t, src, "X-MIB")
	if len(r.Warnings) != 1 || len(r.Manifest.Scalars) != 0 {
		t.Fatalf("%+v", r)
	}
}

func TestSnakeCase(t *testing.T) {
	for in, want := range map[string]string{"cpmCPUTotal5secRev": "cpm_cpu_total5sec_rev", "ifHCInOctets": "if_hc_in_octets", "CISCO-PROCESS": "cisco_process"} {
		if got := snake(in); got != want {
			t.Fatalf("%s: %s", in, got)
		}
	}
}
