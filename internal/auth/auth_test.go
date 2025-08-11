package auth

import (
	"errors"
	"net/http"
	"reflect"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := map[string]struct {
		input       http.Header
		expectedStr string
		expectedErr error
	}{
		"no auth": {
			input: http.Header{
				"Content-Type": []string{"application/json"},
			},
			expectedStr: "",
			expectedErr: ErrNoAuthHeaderIncluded,
		},
		"malformed header len<2": {
			input: http.Header{
				"Authorization": []string{"ApiKey"},
			},
			expectedStr: "",
			expectedErr: errors.New("malformed authorization header"),
		},
		"malformed header bearer": {
			input: http.Header{
				"Authorization": []string{"Bearer S0M3B34R3R"},
			},
			expectedStr: "",
			expectedErr: errors.New("malformed authorization header"),
		},
		"happy path": {
			input: http.Header{
				"Authorization": []string{"ApiKey AAAAAAAAAPPPPPIII"},
			},
			expectedStr: "AAAAAAAAAPPPPPIII",
			expectedErr: nil,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := GetAPIKey(tc.input)
			if !reflect.DeepEqual(tc.expectedErr, err) {
				t.Fatalf("expected error: %v, got error: %v", tc.expectedErr, err)
			}
			if !reflect.DeepEqual(tc.expectedStr, got) {
				t.Fatalf("expected string: %v, got string: %v", tc.expectedStr, got)
			}
		})
	}
}
