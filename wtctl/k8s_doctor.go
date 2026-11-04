package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"text/tabwriter"

	corev1 "k8s.io/api/core/v1"

	"github.com/watchtowerobservability/watchtower-cli/agent/k8s"
)

// k8sMain is `wtctl k8s doctor [-f pods.json]`: lists the pods that carry watchtower.dev
// annotations and says whether the node agent scrapes each one, and why not. Without -f it reads
// `kubectl get pods -A -o json`, so it uses the caller's own kubeconfig and RBAC.
func k8sMain(ctx context.Context, args []string, out io.Writer) error {
	if len(args) == 0 || args[0] != "doctor" {
		return errors.New("usage: wtctl k8s doctor [-f pods.json|-]")
	}
	fs := flag.NewFlagSet("k8s doctor", flag.ContinueOnError)
	file := fs.String("f", "", "a PodList JSON file (- for stdin) instead of running kubectl")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	var raw []byte
	var err error
	switch *file {
	case "":
		raw, err = exec.CommandContext(ctx, "kubectl", "get", "pods", "-A", "-o", "json").Output()
	case "-":
		raw, err = io.ReadAll(os.Stdin)
	default:
		raw, err = os.ReadFile(*file)
	}
	if err != nil {
		return fmt.Errorf("reading pods: %w", err)
	}
	var list corev1.PodList
	if err := json.Unmarshal(raw, &list); err != nil {
		return fmt.Errorf("pods are not a PodList: %w", err)
	}
	return doctorReport(list.Items, out)
}

func doctorReport(pods []corev1.Pod, out io.Writer) error {
	w := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "NAMESPACE\tPOD\tSCRAPED\tTARGET / REASON")
	n := 0
	for i := range pods {
		p := &pods[i]
		annotated := false
		for k := range p.Annotations {
			annotated = annotated || strings.HasPrefix(k, k8s.AnnPrefix)
		}
		if !annotated {
			continue
		}
		n++
		t, why := k8s.Explain(p)
		switch {
		case why != "":
			fmt.Fprintf(w, "%s\t%s\tno\t%s\n", p.Namespace, p.Name, why)
		case t.Integration != "":
			fmt.Fprintf(w, "%s\t%s\tyes\tintegration %s at %s:%d (bound only if the agent config has autodiscovery.integrations.%s)\n",
				p.Namespace, p.Name, t.Integration, t.IP, t.Port, t.Integration)
		default:
			fmt.Fprintf(w, "%s\t%s\tyes\t%s (needs the autodiscovery module enabled on the node agent)\n", p.Namespace, p.Name, t.URL())
		}
	}
	if n == 0 {
		fmt.Fprintln(w, "-\t-\t-\tno pod carries a "+k8s.AnnPrefix+" annotation")
	}
	return w.Flush()
}
