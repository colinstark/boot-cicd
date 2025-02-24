package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	var tests = []struct {
		name          string
		headers       http.Header
		expectedKey   string
		expectedError error
	}{
		{
			name: "Valid API Key",
			headers: http.Header{
				"Authorization": []string{"ApiKey test-api-key"},
			},
			expectedKey:   "test-api-key",
			expectedError: nil,
		},
		{
			name:          "Missing Authorization Header",
			headers:       http.Header{},
			expectedKey:   "",
			expectedError: ErrNoAuthHeaderIncluded,
		},
		{
			name: "Malformed Header - Wrong Format",
			headers: http.Header{
				"Authorization": []string{"Bearer wrong-format"},
			},
			expectedKey:   "",
			expectedError: errors.New("malformed authorization header"),
		},
		{
			name: "Malformed Header - Missing Key",
			headers: http.Header{
				"Authorization": []string{"ApiKey"},
			},
			expectedKey:   "",
			expectedError: errors.New("malformed authorization header"),
		},
	}

	for _, curr_t := range tests {
		t.Run(curr_t.name, func(t *testing.T) {
			gotKey, err := GetAPIKey(curr_t.headers)

			// Check if the error matches what we expect
			if curr_t.expectedError != nil {
				if err == nil {
					t.Errorf("expected error %v, got nil", curr_t.expectedError)
					return
				}
				if err.Error() != curr_t.expectedError.Error() {
					t.Errorf("expected error %v, got %v", curr_t.expectedError, err)
					return
				}
			} else if err != nil {
				t.Errorf("expected no error, got %v", err)
				return
			}

			// Check if the key matches what we expect
			if gotKey != curr_t.expectedKey {
				t.Errorf("expected key %q, got %q", curr_t.expectedKey, gotKey)
			}
		})
	}

}
