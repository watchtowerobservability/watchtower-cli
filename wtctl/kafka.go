package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/twmb/franz-go/pkg/kadm"
	"github.com/twmb/franz-go/pkg/kgo"
	"github.com/twmb/franz-go/pkg/kmsg"
)

const kafkaUsage = "usage: wtctl kafka plan|apply --bootstrap <host:port,...> --principals <file.json> [--prefix <topic prefix>]"

// Principal is one Kafka user and the role that decides its ACLs. Zero quota fields are unset.
type Principal struct {
	User              string  `json:"user"` // SASL/TLS user name, without the "User:" prefix
	Role              string  `json:"role"` // gateway|worker|edge|alerts|notifier
	ProducerByteRate  int64   `json:"producer_byte_rate"`
	ConsumerByteRate  int64   `json:"consumer_byte_rate"`
	RequestPercentage float64 `json:"request_percentage"`
}

// ACL is one allow rule (host "*"). Pattern is "literal" or "prefixed"; Type is "topic" or "group".
type ACL struct {
	Principal, Type, Name, Pattern, Op string
}

// Quota is the client quotas of one user.
type Quota struct {
	User              string
	ProducerByteRate  int64
	ConsumerByteRate  int64
	RequestPercentage float64
}

var otlpSignals = []string{"logs", "traces", "metrics"}

func (a ACL) key() string {
	return strings.Join([]string{a.Principal, a.Type, a.Pattern, a.Name, a.Op}, "|")
}

// roleACLs returns the rules of one principal. Kafka patterns match literals or prefixes only, so
// the worker's retry/slow topics are listed per signal: it never holds Write on a `wt.otlp.<signal>`
// source topic, and the gateway never holds Read on one.
func roleACLs(p Principal, prefix string) ([]ACL, error) {
	u := "User:" + p.User
	var out []ACL
	add := func(typ, name, pattern string, ops ...string) {
		for _, op := range ops {
			out = append(out, ACL{u, typ, prefix + name, pattern, op})
		}
	}
	switch p.Role {
	case "gateway":
		add("topic", "wt.otlp.", "prefixed", "Write", "Describe")
	case "worker":
		add("topic", "wt.otlp.", "prefixed", "Read", "Describe")
		add("topic", "wt.rum", "literal", "Read", "Describe")
		add("topic", "wt.errors", "literal", "Read", "Write", "Describe")
		add("topic", "wt.checks", "literal", "Read", "Write", "Describe")
		add("topic", "wt.dlq.", "prefixed", "Write", "Create", "Describe")
		add("topic", "wt.worker.offsets", "literal", "Read", "Write", "Describe", "Create")
		for _, s := range otlpSignals {
			for _, lane := range []string{".retry", ".slow"} {
				add("topic", "wt.otlp."+s+lane, "literal", "Read", "Write", "Create")
			}
		}
		for _, t := range []string{"wt.errors", "wt.checks", "wt.rum"} {
			add("topic", t+".slow", "literal", "Read", "Write", "Create")
		}
		add("group", "wt-worker-", "prefixed", "Read")
	case "edge":
		add("topic", "wt.errors", "literal", "Write", "Describe")
		add("topic", "wt.checks", "literal", "Write", "Describe")
	case "alerts":
		add("topic", "wt.errors", "literal", "Read", "Describe")
		add("topic", "wt.checks", "literal", "Read", "Describe")
		add("group", "wt-alerts-", "prefixed", "Read")
	case "notifier":
		add("topic", "wt.events", "literal", "Read", "Describe")
		add("group", "wt-notifier-", "prefixed", "Read")
	default:
		return nil, fmt.Errorf("principal %q: unknown role %q", p.User, p.Role)
	}
	return out, nil
}

// Render is the desired state: sorted, de-duplicated ACLs and the quotas of every principal.
func Render(ps []Principal, prefix string) ([]ACL, []Quota, error) {
	seen := map[string]bool{}
	var acls []ACL
	var quotas []Quota
	for _, p := range ps {
		if p.User == "" {
			return nil, nil, errors.New("principal without user")
		}
		as, err := roleACLs(p, prefix)
		if err != nil {
			return nil, nil, err
		}
		for _, a := range as {
			if !seen[a.key()] {
				seen[a.key()] = true
				acls = append(acls, a)
			}
		}
		if p.ProducerByteRate > 0 || p.ConsumerByteRate > 0 || p.RequestPercentage > 0 {
			quotas = append(quotas, Quota{p.User, p.ProducerByteRate, p.ConsumerByteRate, p.RequestPercentage})
		}
	}
	sort.Slice(acls, func(i, j int) bool { return acls[i].key() < acls[j].key() })
	return acls, quotas, nil
}

// kafkaAdmin is the cluster side of plan/apply; tests use a fake.
type kafkaAdmin interface {
	ACLs(ctx context.Context) ([]ACL, error)
	CreateACLs(ctx context.Context, a []ACL) error
	Quotas(ctx context.Context) ([]Quota, error)
	SetQuotas(ctx context.Context, q []Quota) error
}

// Plan is what apply would change. ACLs found on the cluster but not rendered are left alone.
type Plan struct {
	AddACLs   []ACL
	SetQuotas []Quota
}

// Diff compares the desired state with the cluster; an applied plan diffs to nothing.
func Diff(ctx context.Context, adm kafkaAdmin, acls []ACL, quotas []Quota) (Plan, error) {
	haveACL, err := adm.ACLs(ctx)
	if err != nil {
		return Plan{}, err
	}
	haveQ, err := adm.Quotas(ctx)
	if err != nil {
		return Plan{}, err
	}
	has := map[string]bool{}
	for _, a := range haveACL {
		has[a.key()] = true
	}
	var pl Plan
	for _, a := range acls {
		if !has[a.key()] {
			pl.AddACLs = append(pl.AddACLs, a)
		}
	}
	cur := map[string]Quota{}
	for _, q := range haveQ {
		cur[q.User] = q
	}
	for _, q := range quotas {
		if cur[q.User] != q {
			pl.SetQuotas = append(pl.SetQuotas, q)
		}
	}
	return pl, nil
}

func (p Plan) print(w io.Writer) {
	for _, a := range p.AddACLs {
		fmt.Fprintf(w, "+ acl %s allow %s on %s %s (%s)\n", a.Principal, a.Op, a.Type, a.Name, a.Pattern)
	}
	for _, q := range p.SetQuotas {
		fmt.Fprintf(w, "~ quota user=%s producer_byte_rate=%d consumer_byte_rate=%d request_percentage=%g\n",
			q.User, q.ProducerByteRate, q.ConsumerByteRate, q.RequestPercentage)
	}
	if len(p.AddACLs)+len(p.SetQuotas) == 0 {
		fmt.Fprintln(w, "no changes")
	}
}

// kafkaMain is `wtctl kafka plan|apply`.
func kafkaMain(ctx context.Context, args []string, out io.Writer) error {
	if len(args) < 1 || (args[0] != "plan" && args[0] != "apply") {
		return errors.New(kafkaUsage)
	}
	fs := flag.NewFlagSet("kafka "+args[0], flag.ContinueOnError)
	var bootstrap, file, prefix string
	fs.StringVar(&bootstrap, "bootstrap", os.Getenv("WT_KAFKA"), "bootstrap brokers; default $WT_KAFKA")
	fs.StringVar(&file, "principals", "", "principals JSON file")
	fs.StringVar(&prefix, "prefix", "", "topic and group name prefix")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if bootstrap == "" || file == "" {
		return errors.New(kafkaUsage)
	}
	raw, err := os.ReadFile(file)
	if err != nil {
		return err
	}
	var ps []Principal
	if err := json.Unmarshal(raw, &ps); err != nil {
		return fmt.Errorf("principals: %w", err)
	}
	acls, quotas, err := Render(ps, prefix)
	if err != nil {
		return err
	}
	cl, err := kgo.NewClient(kgo.SeedBrokers(strings.Split(bootstrap, ",")...))
	if err != nil {
		return err
	}
	defer cl.Close()
	adm := &franzAdmin{cl: cl, ad: kadm.NewClient(cl)}
	pl, err := Diff(ctx, adm, acls, quotas)
	if err != nil {
		return err
	}
	pl.print(out)
	if args[0] == "plan" {
		return nil
	}
	if err := adm.CreateACLs(ctx, pl.AddACLs); err != nil {
		return err
	}
	return adm.SetQuotas(ctx, pl.SetQuotas)
}

var opCodes = map[string]kmsg.ACLOperation{
	"Read": kmsg.ACLOperationRead, "Write": kmsg.ACLOperationWrite,
	"Describe": kmsg.ACLOperationDescribe, "Create": kmsg.ACLOperationCreate,
}

func opName(o kmsg.ACLOperation) string {
	for n, c := range opCodes {
		if c == o {
			return n
		}
	}
	return ""
}

func kerr(code int16, msg *string) error {
	if code == 0 {
		return nil
	}
	if msg != nil {
		return fmt.Errorf("kafka error %d: %s", code, *msg)
	}
	return fmt.Errorf("kafka error %d", code)
}

// franzAdmin applies the plan through the Kafka admin API (franz-go kgo, kmsg and kadm).
type franzAdmin struct {
	cl *kgo.Client
	ad *kadm.Client
}

func (f *franzAdmin) ACLs(ctx context.Context) ([]ACL, error) {
	req := kmsg.NewPtrDescribeACLsRequest()
	req.ResourceType = kmsg.ACLResourceTypeAny
	req.ResourcePatternType = kmsg.ACLResourcePatternTypeAny
	req.Operation = kmsg.ACLOperationAny
	req.PermissionType = kmsg.ACLPermissionTypeAllow
	resp, err := req.RequestWith(ctx, f.cl)
	if err != nil {
		return nil, err
	}
	if err := kerr(resp.ErrorCode, resp.ErrorMessage); err != nil {
		return nil, err
	}
	var out []ACL
	for _, r := range resp.Resources {
		typ := "topic"
		switch r.ResourceType {
		case kmsg.ACLResourceTypeGroup:
			typ = "group"
		case kmsg.ACLResourceTypeTopic:
		default:
			continue
		}
		pat := "literal"
		if r.ResourcePatternType == kmsg.ACLResourcePatternTypePrefixed {
			pat = "prefixed"
		}
		for _, a := range r.ACLs {
			if a.Host == "*" && opName(a.Operation) != "" {
				out = append(out, ACL{a.Principal, typ, r.ResourceName, pat, opName(a.Operation)})
			}
		}
	}
	return out, nil
}

func (f *franzAdmin) CreateACLs(ctx context.Context, acls []ACL) error {
	if len(acls) == 0 {
		return nil
	}
	req := kmsg.NewPtrCreateACLsRequest()
	for _, a := range acls {
		c := kmsg.NewCreateACLsRequestCreation()
		c.ResourceType = kmsg.ACLResourceTypeTopic
		if a.Type == "group" {
			c.ResourceType = kmsg.ACLResourceTypeGroup
		}
		c.ResourceName = a.Name
		c.ResourcePatternType = kmsg.ACLResourcePatternTypeLiteral
		if a.Pattern == "prefixed" {
			c.ResourcePatternType = kmsg.ACLResourcePatternTypePrefixed
		}
		c.Principal, c.Host = a.Principal, "*"
		c.Operation = opCodes[a.Op]
		c.PermissionType = kmsg.ACLPermissionTypeAllow
		req.Creations = append(req.Creations, c)
	}
	resp, err := req.RequestWith(ctx, f.cl)
	if err != nil {
		return err
	}
	for _, r := range resp.Results {
		if err := kerr(r.ErrorCode, r.ErrorMessage); err != nil {
			return err
		}
	}
	return nil
}

var quotaKeys = [3]string{"producer_byte_rate", "consumer_byte_rate", "request_percentage"}

// Quotas reads every user-scoped quota entry.
func (f *franzAdmin) Quotas(ctx context.Context) ([]Quota, error) {
	req := kmsg.NewPtrDescribeClientQuotasRequest()
	c := kmsg.NewDescribeClientQuotasRequestComponent()
	c.EntityType = "user"
	c.MatchType = 2 // any specified name
	req.Components = append(req.Components, c)
	resp, err := req.RequestWith(ctx, f.cl)
	if err != nil {
		return nil, err
	}
	if err := kerr(resp.ErrorCode, resp.ErrorMessage); err != nil {
		return nil, err
	}
	var out []Quota
	for _, e := range resp.Entries {
		if len(e.Entity) != 1 || e.Entity[0].Name == nil {
			continue
		}
		q := Quota{User: *e.Entity[0].Name}
		for _, v := range e.Values {
			switch v.Key {
			case quotaKeys[0]:
				q.ProducerByteRate = int64(v.Value)
			case quotaKeys[1]:
				q.ConsumerByteRate = int64(v.Value)
			case quotaKeys[2]:
				q.RequestPercentage = v.Value
			}
		}
		out = append(out, q)
	}
	return out, nil
}

func (f *franzAdmin) SetQuotas(ctx context.Context, qs []Quota) error {
	var entries []kadm.AlterClientQuotaEntry
	for _, q := range qs {
		user := q.User
		e := kadm.AlterClientQuotaEntry{Entity: kadm.ClientQuotaEntity{{Type: "user", Name: &user}}}
		vals := [3]float64{float64(q.ProducerByteRate), float64(q.ConsumerByteRate), q.RequestPercentage}
		for i, k := range quotaKeys {
			e.Ops = append(e.Ops, kadm.AlterClientQuotaOp{Key: k, Value: vals[i], Remove: vals[i] == 0})
		}
		entries = append(entries, e)
	}
	if len(entries) == 0 {
		return nil
	}
	_, err := f.ad.AlterClientQuotas(ctx, entries)
	return err
}
