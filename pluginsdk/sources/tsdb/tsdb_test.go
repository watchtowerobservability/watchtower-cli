package tsdb

import (
	"net/url"
	"strings"
	"testing"
	"time"
)

var (
	from = time.Unix(1000, 0)
	to   = time.Unix(2000, 0)
)

func TestSplitRefusesAnythingButAHost(t *testing.T) {
	if h, q, err := Split(" a.example.com:8086 | SELECT 1 "); err != nil || h != "a.example.com:8086" || q != "SELECT 1" {
		t.Fatal(h, q, err)
	}
	for _, bad := range []string{"SELECT 1", "a.example.com|", "a/b|q", "a@b|q", "https://a|q", "|q"} {
		if _, _, err := Split(bad); err == nil {
			t.Fatal(bad)
		}
	}
}

func TestGraphite(t *testing.T) {
	if p := GraphitePath("a.b", from, to); !strings.Contains(p, "target=a.b") || !strings.Contains(p, "from=1000") || !strings.Contains(p, "until=2000") {
		t.Fatal(p)
	}
	f, err := ParseGraphite([]byte(`[{"target":"a.b","datapoints":[[2,1060],[null,1120],[1,1000]]}]`))
	if err != nil || len(f.Frames) != 1 {
		t.Fatal(f, err)
	}
	vals := f.Frames[0].Fields[1].Values
	if f.Frames[0].Name != "a.b" || len(vals) != 2 || vals[0] != 1.0 || vals[1] != 2.0 {
		t.Fatal("nulls go and times sort", vals)
	}
	if _, err := ParseGraphite([]byte(`{`)); err == nil {
		t.Fatal("bad json")
	}
}

func TestInflux(t *testing.T) {
	u, err := url.Parse(InfluxPath("metrics", "SELECT mean(v) FROM cpu WHERE $timeFilter", from, to))
	if err != nil {
		t.Fatal(err)
	}
	if u.Query().Get("db") != "metrics" || u.Query().Get("q") != "SELECT mean(v) FROM cpu WHERE time >= 1000s AND time < 2000s" {
		t.Fatal(u)
	}
	f, err := ParseInflux([]byte(`{"results":[{"series":[{"name":"cpu","tags":{"host":"a"},"columns":["time","mean","max"],"values":[[1000,1,2],[1060,null,3]]}]}]}`))
	if err != nil || len(f.Frames) != 2 || f.Frames[0].Name != `cpu.mean{host="a"}` || len(f.Frames[0].Fields[1].Values) != 1 || len(f.Frames[1].Fields[1].Values) != 2 {
		t.Fatal(f, err)
	}
	if _, err := ParseInflux([]byte(`{"results":[{"error":"no such db"}]}`)); err == nil || err.Error() != "no such db" {
		t.Fatal(err)
	}
}

func TestOpenTSDB(t *testing.T) {
	if p := OpenTSDBPath("sum:sys.cpu{host=a}", from, to); !strings.Contains(p, "start=1000") || !strings.Contains(p, "end=2000") {
		t.Fatal(p)
	}
	f, err := ParseOpenTSDB([]byte(`[{"metric":"sys.cpu","tags":{"host":"a"},"dps":{"1060":2,"1000":1,"1120":null}}]`))
	if err != nil || len(f.Frames) != 1 || f.Frames[0].Name != `sys.cpu{host="a"}` || f.Frames[0].Fields[1].Values[0] != 1.0 || len(f.Frames[0].Fields[1].Values) != 2 {
		t.Fatal(f, err)
	}
}
