package tsdb

import (
	"strings"
	"testing"
)

func TestFluxRequestPutsTheRangeIn(t *testing.T) {
	p, body, err := FluxRequest("acme", `from(bucket:"b") |> range(start: v.timeRangeStart, stop: v.timeRangeStop)`, from, to)
	if err != nil || p != "/api/v2/query?org=acme" {
		t.Fatal(p, err)
	}
	if s := string(body); !strings.Contains(s, "1970-01-01T00:16:40Z") || !strings.Contains(s, "1970-01-01T00:33:20Z") || strings.Contains(s, "timeRange") {
		t.Fatal(s)
	}
}

func TestParseFluxSplitsTablesAndKeepsTags(t *testing.T) {
	csv := ",result,table,_start,_stop,_time,_value,_field,_measurement,host\r\n" +
		",_result,0,x,y,1970-01-01T00:16:40Z,1.5,usage,cpu,a\r\n" +
		",_result,0,x,y,1970-01-01T00:17:40Z,2,usage,cpu,a\r\n" +
		",_result,1,x,y,1970-01-01T00:16:40Z,7,usage,cpu,b\r\n" +
		"\r\n" +
		",result,table,_time,_value,_field,_measurement\r\n" +
		",_result,0,1970-01-01T00:16:40Z,on,state,door\r\n"
	f, err := ParseFlux([]byte(csv))
	if err != nil {
		t.Fatal(err)
	}
	if len(f.Frames) != 2 || f.Frames[0].Name != `cpu.usage{host="a"}` || f.Frames[1].Name != `cpu.usage{host="b"}` {
		t.Fatalf("%+v", f.Frames)
	}
	if got := f.Frames[0].Fields[1].Values; len(got) != 2 || got[0] != 1.5 {
		t.Fatal(got)
	}
	if _, err := ParseFlux([]byte("error,reference\r\nbucket not found,404\r\n")); err == nil || err.Error() != "bucket not found" {
		t.Fatal(err)
	}
}
