package agents

import (
	"context"
	"strings"
	"testing"
)

// TestNtfyValidate verifies the ntfy provider's Validate logic across all
// relevant configurations: missing URL, invalid scheme, token being optional,
// and valid http/https URLs including self-hosted LAN addresses.
func TestNtfyValidate(t *testing.T) {
	tests := []struct {
		name    string
		agent   Agent
		wantErr string
	}{
		{
			name:    "missing topic URL",
			agent:   Agent{Name: "Ntfy", Type: "ntfy"},
			wantErr: "ntfy topic URL is required",
		},
		{
			name: "invalid scheme",
			agent: Agent{Name: "Ntfy", Type: "ntfy", Config: Config{
				NtfyTopicURL: "ftp://ntfy.sh/alerts",
			}},
			wantErr: "ntfy topic URL must start with http://",
		},
		{
			name: "valid without token",
			agent: Agent{Name: "Ntfy", Type: "ntfy", Config: Config{
				NtfyTopicURL: "https://ntfy.sh/my-alerts",
			}},
		},
		{
			name: "valid with token",
			agent: Agent{Name: "Ntfy", Type: "ntfy", Config: Config{
				NtfyTopicURL: "https://ntfy.sh/my-alerts",
				NtfyToken:    "tk_secret",
			}},
		},
		{
			name: "valid self-hosted http",
			agent: Agent{Name: "Ntfy", Type: "ntfy", Config: Config{
				NtfyTopicURL: "http://192.168.1.10:9090/clonarr",
			}},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateAgent(tc.agent)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("ValidateAgent() unexpected error: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("ValidateAgent() expected error containing %q, got nil", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("ValidateAgent() error = %q, want contains %q", err.Error(), tc.wantErr)
			}
		})
	}
}

// TestNtfyMaskAndPreserve verifies the credential mask/preserve round-trip:
// MaskConfigByType replaces the access token with a placeholder, and
// PreserveConfigByType restores the original when that placeholder is submitted
// back. NtfyTopicURL is not a bearer credential and must not be masked.
func TestNtfyMaskAndPreserve(t *testing.T) {
	cfg := Config{
		NtfyTopicURL: "https://ntfy.sh/my-alerts",
		NtfyToken:    "tk_secret",
	}

	masked := MaskConfigByType("ntfy", cfg)
	if masked.NtfyToken != maskedToken {
		t.Fatalf("token not masked: got %q", masked.NtfyToken)
	}
	if masked.NtfyTopicURL != cfg.NtfyTopicURL {
		t.Fatalf("topic URL should not be masked: got %q", masked.NtfyTopicURL)
	}

	restored := PreserveConfigByType("ntfy", masked, cfg)
	if restored.NtfyToken != cfg.NtfyToken {
		t.Fatalf("token not preserved: got %q", restored.NtfyToken)
	}
}

// TestNtfyTestHappyPath verifies that Test sends a probe to the configured
// topic URL and returns an OK result when the HTTP client returns 200.
func TestNtfyTestHappyPath(t *testing.T) {
	mock := newOKPoster()
	rt := testRuntime(mock, nil)
	agent := Agent{Name: "Ntfy", Type: "ntfy", Config: Config{
		NtfyTopicURL: "https://ntfy.sh/my-alerts",
	}}

	results, err := ntfyProvider{}.Test(context.Background(), rt, agent)
	if err != nil {
		t.Fatalf("Test() error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].Status != statusOK {
		t.Fatalf("expected OK, got status=%q error=%q", results[0].Status, results[0].Error)
	}
	if mock.lastURL != "https://ntfy.sh/my-alerts" {
		t.Fatalf("unexpected request URL: %q", mock.lastURL)
	}
}

// TestNtfyTestHTTPError verifies that Test captures network errors and returns
// them as a TestResult error rather than a top-level error, so the UI can
// display the failure without treating it as an invalid request.
func TestNtfyTestHTTPError(t *testing.T) {
	mock := newErrorPoster("connection refused")
	rt := testRuntime(mock, nil)
	agent := Agent{Name: "Ntfy", Type: "ntfy", Config: Config{
		NtfyTopicURL: "https://ntfy.sh/my-alerts",
	}}

	results, err := ntfyProvider{}.Test(context.Background(), rt, agent)
	if err != nil {
		t.Fatalf("Test() should not return top-level error: %v", err)
	}
	if results[0].Status != statusError {
		t.Fatalf("expected error status, got %q", results[0].Status)
	}
	if !strings.Contains(results[0].Error, "connection refused") {
		t.Fatalf("error should contain 'connection refused': %q", results[0].Error)
	}
}

// TestNtfyTestHTTPStatus verifies that Test reports HTTP error status codes,
// e.g. 401 Unauthorized returned by an authenticated server when no token
// or a bad token is supplied.
func TestNtfyTestHTTPStatus(t *testing.T) {
	mock := newStatusPoster(401)
	rt := testRuntime(mock, nil)
	agent := Agent{Name: "Ntfy", Type: "ntfy", Config: Config{
		NtfyTopicURL: "https://ntfy.sh/my-alerts",
		NtfyToken:    "bad-token",
	}}

	results, err := ntfyProvider{}.Test(context.Background(), rt, agent)
	if err != nil {
		t.Fatalf("Test() error: %v", err)
	}
	if results[0].Status != statusError {
		t.Fatalf("expected error for 401, got %q", results[0].Status)
	}
}

// TestNtfyTestNilClient verifies that Test returns a top-level error when
// NotifyClient is not configured, preventing a nil-pointer panic at dispatch.
func TestNtfyTestNilClient(t *testing.T) {
	rt := testRuntime(nil, nil)
	agent := Agent{Name: "Ntfy", Type: "ntfy", Config: Config{
		NtfyTopicURL: "https://ntfy.sh/my-alerts",
	}}

	_, err := ntfyProvider{}.Test(context.Background(), rt, agent)
	if err == nil {
		t.Fatal("expected error when NotifyClient is nil")
	}
}

// TestNtfyTestMissingURL verifies that Test returns a top-level error when
// the topic URL is empty rather than attempting a malformed HTTP request.
func TestNtfyTestMissingURL(t *testing.T) {
	rt := testRuntime(newOKPoster(), nil)
	agent := Agent{Name: "Ntfy", Type: "ntfy", Config: Config{}}

	_, err := ntfyProvider{}.Test(context.Background(), rt, agent)
	if err == nil {
		t.Fatal("expected error when topic URL is missing")
	}
	if !strings.Contains(err.Error(), "ntfy topic URL is required") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestNtfyNotifyHappyPath verifies that Notify sends to the topic URL
// and returns nil on a successful HTTP response.
func TestNtfyNotifyHappyPath(t *testing.T) {
	mock := newOKPoster()
	rt := testRuntime(mock, nil)
	agent := Agent{Name: "Ntfy", Type: "ntfy", Enabled: true, Config: Config{
		NtfyTopicURL: "https://ntfy.sh/my-alerts",
	}}

	err := ntfyProvider{}.Notify(context.Background(), rt, agent, Payload{
		Title:    "Test",
		Message:  "body",
		Severity: SeverityInfo,
	})
	if err != nil {
		t.Fatalf("Notify() error: %v", err)
	}
	if mock.lastURL != "https://ntfy.sh/my-alerts" {
		t.Fatalf("unexpected request URL: %q", mock.lastURL)
	}
}

// TestNtfyNotifyHTTPError verifies that Notify returns an error when the
// server responds with a 4xx or 5xx status code.
func TestNtfyNotifyHTTPError(t *testing.T) {
	mock := newStatusPoster(500)
	rt := testRuntime(mock, nil)
	agent := Agent{Name: "Ntfy", Type: "ntfy", Enabled: true, Config: Config{
		NtfyTopicURL: "https://ntfy.sh/my-alerts",
	}}

	err := ntfyProvider{}.Notify(context.Background(), rt, agent, Payload{Severity: SeverityInfo})
	if err == nil {
		t.Fatal("expected error on 500")
	}
}

// TestNtfyNotifyNilClient verifies that Notify returns an error when
// NotifyClient is not configured, preventing a nil-pointer panic.
func TestNtfyNotifyNilClient(t *testing.T) {
	rt := testRuntime(nil, nil)
	agent := Agent{Name: "Ntfy", Type: "ntfy", Enabled: true, Config: Config{
		NtfyTopicURL: "https://ntfy.sh/my-alerts",
	}}

	err := ntfyProvider{}.Notify(context.Background(), rt, agent, Payload{Severity: SeverityInfo})
	if err == nil {
		t.Fatal("expected error when NotifyClient is nil")
	}
}

// TestNtfyNotifyMissingURL verifies that Notify silently skips delivery when
// the topic URL is empty. This covers the case where an agent is disabled or
// misconfigured after dispatch was already queued.
func TestNtfyNotifyMissingURL(t *testing.T) {
	rt := testRuntime(newOKPoster(), nil)
	agent := Agent{Name: "Ntfy", Type: "ntfy", Enabled: true, Config: Config{}}

	err := ntfyProvider{}.Notify(context.Background(), rt, agent, Payload{Severity: SeverityInfo})
	if err != nil {
		t.Fatalf("expected nil for missing URL, got: %v", err)
	}
}

// TestNtfyPriority verifies severity-to-priority string mapping:
// critical → "5" (urgent), warning → "3" (default), info → "3" (default).
// Unset and unrecognised severities both fall back to the default priority.
func TestNtfyPriority(t *testing.T) {
	tests := []struct {
		severity Severity
		want     string
	}{
		{SeverityCritical, "5"},
		{SeverityWarning, "3"},
		{SeverityInfo, "3"},
		{"", "3"},        // unset severity defaults to normal
		{"unknown", "3"}, // unrecognised severity defaults to normal
	}
	for _, tc := range tests {
		got := ntfyPriority(tc.severity)
		if got != tc.want {
			t.Errorf("ntfyPriority(%q) = %q, want %q", tc.severity, got, tc.want)
		}
	}
}
