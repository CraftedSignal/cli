package schema

import (
	"reflect"
	"testing"
)

func TestGetDataDecodesSampleEvents(t *testing.T) {
	tests := []struct {
		name string
		test Test
		want []map[string]interface{}
	}{
		{"yaml wins over json", Test{Data: []map[string]interface{}{{"source": "yaml"}}, JSON: `{"source":"json"}`}, []map[string]interface{}{{"source": "yaml"}}},
		{"json event list", Test{JSON: `[{"EventID":4625},{"EventID":4624}]`}, []map[string]interface{}{{"EventID": float64(4625)}, {"EventID": float64(4624)}}},
		{"single json event", Test{JSON: `{"user":"alice","failed":true}`}, []map[string]interface{}{{"user": "alice", "failed": true}}},
		{"empty json list", Test{JSON: `[]`}, []map[string]interface{}{}},
		{"malformed json", Test{JSON: `{"user":`}, nil},
		{"scalar json", Test{JSON: `42`}, nil},
		{"mixed list", Test{JSON: `[{"user":"alice"},42]`}, nil},
		{"no sample", Test{}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.test.GetData(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("decoded events = %#v; want %#v", got, tt.want)
			}
		})
	}
}
