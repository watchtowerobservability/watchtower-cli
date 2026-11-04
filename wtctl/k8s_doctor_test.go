package main

import (
	"bytes"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestK8sDoctorExplainsEachAnnotatedPod(t *testing.T) {
	running := corev1.PodStatus{PodIP: "10.0.0.5", Phase: corev1.PodRunning}
	pods := []corev1.Pod{
		{ObjectMeta: metav1.ObjectMeta{Namespace: "a", Name: "ok", Annotations: map[string]string{"watchtower.dev/scrape": "true", "watchtower.dev/port": "9100"}}, Status: running},
		{ObjectMeta: metav1.ObjectMeta{Namespace: "a", Name: "typo", Annotations: map[string]string{"watchtower.dev/scrape": "yes"}}, Status: running},
		{ObjectMeta: metav1.ObjectMeta{Namespace: "a", Name: "plain"}, Status: running},
	}
	var b bytes.Buffer
	if err := doctorReport(pods, &b); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	if !strings.Contains(out, "http://10.0.0.5:9100/metrics") || !strings.Contains(out, `scrape is not "true"`) || strings.Contains(out, "plain") {
		t.Fatalf("report:\n%s", out)
	}
}
