// main_test.go
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/spf13/cobra"
	"github.com/zalando/go-keyring" // Import keyring for ErrNotFound
	"golang.org/x/oauth2"
)

// --- Test Helpers ---

// Mock Keyring state
var (
	mockKeyringStore      = make(map[string]map[string]string)
	mockKeyringMu         sync.Mutex
	keyringSetError       error         // Injectable error for Set
	keyringGetError       error         // Injectable error for Get
	originalKeyringSet    = keyring.Set // Backup original functions
	originalKeyringGet    = keyring.Get
	originalKeyringDelete = keyring.Delete // If you add delete functionality
)

// mockKeyringSet replaces keyring.Set for testing
func mockKeyringSet(service, user, password string) error {
	mockKeyringMu.Lock()
	defer mockKeyringMu.Unlock()
	if keyringSetError != nil {
		return keyringSetError
	}
	if _, ok := mockKeyringStore[service]; !ok {
		mockKeyringStore[service] = make(map[string]string)
	}
	mockKeyringStore[service][user] = password
	return nil
}

// mockKeyringGet replaces keyring.Get for testing
func mockKeyringGet(service, user string) (string, error) {
	mockKeyringMu.Lock()
	defer mockKeyringMu.Unlock()
	if keyringGetError != nil {
		// Special handling for ErrNotFound simulation
		if errors.Is(keyringGetError, keyring.ErrNotFound) {
			return "", keyring.ErrNotFound
		}
		return "", keyringGetError
	}
	if serviceStore, ok := mockKeyringStore[service]; ok {
		if password, ok := serviceStore[user]; ok {
			return password, nil
		}
	}
	return "", keyring.ErrNotFound // Default to not found if not mocked otherwise
}

// Helper to setup/teardown keyring mocks
func setupKeyringMocks(t *testing.T) {
	t.Helper()
	mockKeyringMu.Lock()
	// Reset state for each test
	mockKeyringStore = make(map[string]map[string]string)
	keyringSetError = nil
	keyringGetError = nil
	mockKeyringMu.Unlock()

	keyring.Set = mockKeyringSet
	keyring.Get = mockKeyringGet
	// keyring.Delete = mockKeyringDelete // If needed

	// Restore original functions after test
	t.Cleanup(func() {
		keyring.Set = originalKeyringSet
		keyring.Get = originalKeyringGet
		// keyring.Delete = originalKeyringDelete // If needed
	})
}

// Mock exec.Command state
var (
	mockExecCommand func(command string, args ...string) *exec.Cmd
	originalCommand = exec.Command // Backup original
)

// Test 'exec' command helper for mocking
func helperCommand(t *testing.T, command string, args ...string) *exec.Cmd {
	t.Helper()
	cs := []string{"-test.run=TestHelperProcess", "--", command}
	cs = append(cs, args...)
	cmd := exec.Command(os.Args[0], cs...)
	// Set environment variables to control mock process behavior
	cmd.Env = []string{"GO_WANT_HELPER_PROCESS=1"}
	return cmd
}

// TestHelperProcess isn't a real test. It's used as a stub process.
func TestHelperProcess(t *testing.T) {
	if os.Getenv("GO_WANT_HELPER_PROCESS") != "1" {
		return
	}
	defer os.Exit(0)

	args := os.Args
	for len(args) > 0 {
		if args[0] == "--" {
			args = args[1:]
			break
		}
		args = args[1:]
	}
	if len(args) == 0 {
		fmt.Fprintf(os.Stderr, "No command\n")
		os.Exit(2)
	}

	cmd, args := args[0], args[1:]
	// Simulate specific git commands
	switch cmd {
	case "git":
		if len(args) > 0 && args[0] == "diff" {
			mockOutput := os.Getenv("GIT_DIFF_MOCK_OUTPUT")
			mockStderr := os.Getenv("GIT_DIFF_MOCK_STDERR")
			mockExitCode := os.Getenv("GIT_DIFF_MOCK_EXIT_CODE")

			fmt.Fprint(os.Stdout, mockOutput)
			fmt.Fprint(os.Stderr, mockStderr)
			if mockExitCode != "" && mockExitCode != "0" {
				// Simulate non-zero exit code
				os.Exit(1) // Or parse mockExitCode for specific code
			}
			os.Exit(0)
		} else if len(args) > 0 && args[0] == "commit" {
			// Read stdin (the commit message) to potentially verify it
			// stdinBytes, _ := io.ReadAll(os.Stdin)
			// fmt.Fprintf(os.Stderr, "Commit message received: %s", string(stdinBytes))

			mockStderr := os.Getenv("GIT_COMMIT_MOCK_STDERR")
			mockExitCode := os.Getenv("GIT_COMMIT_MOCK_EXIT_CODE")

			fmt.Fprint(os.Stderr, mockStderr)
			if mockExitCode != "" && mockExitCode != "0" {
				os.Exit(1)
			}
			os.Exit(0)
		}
	default:
		fmt.Fprintf(os.Stderr, "Unknown command %q\n", cmd)
		os.Exit(2)
	}
}

// Helper to setup/teardown exec mocks
func setupExecMocks(t *testing.T) {
	t.Helper()
	// Default mock points to the helper process
	mockExecCommand = func(command string, args ...string) *exec.Cmd {
		return helperCommand(t, command, args...)
	}
	execCommand = mockExecCommand // Assuming you refactor main.go to use a variable `var execCommand = exec.Command`

	// If you haven't refactored main.go, this is harder.
	// You might need to use monkey patching libraries (like bouk/monkey)
	// or structure your code to accept an 'executor' interface.
	// For now, let's *assume* you can swap the function via a variable:
	// In main.go: var execCommand = exec.Command
	// Then here: originalCommand := execCommand; execCommand = mockExecCommand; t.Cleanup(func() { execCommand = originalCommand })

	// **Important:** The provided main.go doesn't use a variable.
	// These exec tests will **FAIL** without refactoring main.go or using monkey patching.
	// We will write the tests assuming the refactor for demonstration.
	// If refactoring isn't possible, these specific tests (`TestGetGitDiff`, `TestCommitWithGeneratedMessage`) need a different approach.

	// Let's assume the refactor for now:
	originalCmdFunc := execCommand // Store the original function (which should be exec.Command initially)
	execCommand = mockExecCommand  // Replace with our mock dispatcher
	t.Cleanup(func() {
		execCommand = originalCmdFunc // Restore original
		// Clear env vars used by mock
		os.Unsetenv("GIT_DIFF_MOCK_OUTPUT")
		os.Unsetenv("GIT_DIFF_MOCK_STDERR")
		os.Unsetenv("GIT_DIFF_MOCK_EXIT_CODE")
		os.Unsetenv("GIT_COMMIT_MOCK_STDERR")
		os.Unsetenv("GIT_COMMIT_MOCK_EXIT_CODE")
	})
}

// --- Unit Tests ---

func TestContains(t *testing.T) {
	tests := []struct {
		name  string
		slice []string
		item  string
		want  bool
	}{
		{"found simple", []string{"feat", "fix", "chore"}, "fix", true},
		{"found case insensitive", []string{"feat", "Fix", "chore"}, "fix", true},
		{"found case insensitive item", []string{"feat", "fix", "chore"}, "FIX", true},
		{"not found", []string{"feat", "fix", "chore"}, "docs", false},
		{"empty slice", []string{}, "feat", false},
		{"empty item", []string{"feat", ""}, "", true},
		{"nil slice", nil, "feat", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := contains(tt.slice, tt.item); got != tt.want {
				t.Errorf("contains() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGenerateRandomString(t *testing.T) {
	tests := []struct {
		name    string
		n       int
		wantErr bool
	}{
		{"standard length", 32, false},
		{"zero length", 0, false},
		{"short length", 1, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := generateRandomString(tt.n)
			if (err != nil) != tt.wantErr {
				t.Errorf("generateRandomString() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err == nil {
				// Check length - Base64 raw URL encoding length calculation
				expectedLen := (tt.n*8 + 5) / 6
				if len(got) != expectedLen {
					t.Errorf("generateRandomString() len = %v, want len %v (for n=%d)", len(got), expectedLen, tt.n)
				}
				// Basic check for base64 characters (URL safe variant)
				for _, r := range got {
					if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_') {
						t.Errorf("generateRandomString() got %q, contains invalid base64 raw URL char %c", got, r)
						break
					}
				}
			}
		})
	}
}

func TestGenerateSuggestedSubject(t *testing.T) {
	// Setup default config for tests
	originalConfig := commitMessageConfig
	commitMessageConfig = CommitMessageConfig{
		MaxSubjectLength: 50,
		// ScopeKeywords and TypeKeywords aren't used by this func, but set for completeness
		ScopeKeywords: []string{"feat", "fix"},
		TypeKeywords:  []string{"test"},
	}
	t.Cleanup(func() { commitMessageConfig = originalConfig }) // Restore

	tests := []struct {
		name string
		diff string
		want string
	}{
		{"simple addition", "diff --git a/file.txt b/file.txt\n--- a/file.txt\n+++ b/file.txt\n@@ -1,1 +1,1 @@\n-hello\n+hello world", "hello world"},
		{"simple deletion", "diff --git a/file.txt b/file.txt\n--- a/file.txt\n+++ b/file.txt\n@@ -1,1 +0,0 @@\n-remove this line", "Remove remove this line"},
		{"modification picks add", "diff --git a/file.txt b/file.txt\n--- a/file.txt\n+++ b/file.txt\n@@ -1,1 +1,1 @@\n-old line\n+new line", "new line"},
		{"only file rename", "diff --git a/old.txt b/new.txt\nsimilarity index 100%\nrename from old.txt\nrename to new.txt", "Update new.txt"},
		{"only file mode change", "diff --git a/script.sh b/script.sh\nold mode 100644\nnew mode 100755", "Update script.sh"},
		{"long addition truncated", "diff --git a/long.txt b/long.txt\n+++ b/long.txt\n+This is a very long line that definitely exceeds the maximum subject length of fifty characters", "This is a very long line that definitely exceeds..."},
		{"long deletion truncated", "diff --git a/long.txt b/long.txt\n--- a/long.txt\n-This is a very long line that was deleted and exceeds the maximum subject length of fifty chars", "Remove This is a very long line that was deleted..."},
		{"long filename truncated", "diff --git a/a_very_very_long_filename_that_needs_truncation.go b/a_very_very_long_filename_that_needs_truncation.go\nindex abc..def 100644\n--- a/a_very_very_long_filename_that_needs_truncation.go\n+++ b/a_very_very_long_filename_that_needs_truncation.go", "Update a_very_very_long_filename_that_needs_t..."},
		{"empty diff", "", "Update code"},
		{"diff with only headers", "diff --git a/file.txt b/file.txt\nindex abc..def 100644\n--- a/file.txt\n+++ b/file.txt", "Update file.txt"},
		{"diff with complex path", "diff --git a/src/components/button.tsx b/src/components/button.tsx\n--- a/src/components/button.tsx\n+++ b/src/components/button.tsx\n+ added button logic", "added button logic"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := generateSuggestedSubject(tt.diff); got != tt.want {
				t.Errorf("generateSuggestedSubject() = %q, want %q", got, tt.want)
			}
		})
	}
}

// NOTE: TestGetGitDiff and TestCommitWithGeneratedMessage require refactoring main.go
// to use a variable for exec.Command (e.g., var execCommand = exec.Command)
// or using a monkey-patching library. The tests below assume the refactor.

/* // Uncomment and adapt if main.go is refactored or using monkey patching
func TestGetGitDiff(t *testing.T) {
	setupExecMocks(t) // Sets up the mock execCommand variable

	tests := []struct {
		name           string
		stagedOutput   string
		stagedErr      string
		stagedExitCode string
		workingOutput  string
		workingErr     string
		workingExitCode string
		wantDiff       string
		wantErr        bool
	}{
		{
			name:          "staged and working",
			stagedOutput:  " M file1.txt\n",
			workingOutput: "?? file2.txt\n",
			wantDiff:      " M file1.txt\n\n?? file2.txt", // Note: TrimSpace adds newline if both present
			wantErr:       false,
		},
		{
			name:         "only staged",
			stagedOutput: " M file1.txt\n",
			wantDiff:     " M file1.txt",
			wantErr:      false,
		},
		{
			name:          "only working",
			workingOutput: "?? file2.txt\n",
			wantDiff:      "?? file2.txt",
			wantErr:       false,
		},
		{
			name:     "no changes",
			wantDiff: "",
			wantErr:  false,
		},
		{
			name:           "staged error",
			stagedErr:      "git error staged",
			stagedExitCode: "1",
			workingOutput:  "?? file2.txt\n",
			wantDiff:       "?? file2.txt", // Still returns working diff
			wantErr:        true,          // But reports error
		},
		{
			name:            "working error",
			stagedOutput:    " M file1.txt\n",
			workingErr:      "git error working",
			workingExitCode: "1",
			wantDiff:        " M file1.txt", // Still returns staged diff
			wantErr:         true,           // But reports error
		},
		{
			name:            "both error",
			stagedErr:       "git error staged",
			stagedExitCode:  "1",
			workingErr:      "git error working",
			workingExitCode: "1",
			wantDiff:        "",   // No diff returned if both fail
			wantErr:         true, // Reports combined error
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Configure the mock process via environment variables
			os.Setenv("GIT_DIFF_MOCK_OUTPUT", tt.stagedOutput) // Assume first call is --cached
			os.Setenv("GIT_DIFF_MOCK_STDERR", tt.stagedErr)
			os.Setenv("GIT_DIFF_MOCK_EXIT_CODE", tt.stagedExitCode)

			// Need a way to change env vars between the two calls within getGitDiff
			// This simple mock setup isn't sufficient for that.
			// A more sophisticated mockExecCommand would be needed, maybe using channels
			// or inspecting args to decide which output to give.

			// --- Simplified Test ---
			// Let's test only one call for now to show the principle
			// Test case: only staged diff works
			os.Setenv("GIT_DIFF_MOCK_OUTPUT", " M staged.txt\n")
			os.Setenv("GIT_DIFF_MOCK_STDERR", "")
			os.Setenv("GIT_DIFF_MOCK_EXIT_CODE", "0")
			// How to make the *second* call return empty? The mock isn't stateful.
			// This highlights the limitation of the simple TestHelperProcess approach
			// for multi-call functions.

			// --- Alternative: Test error handling ---
			// Test case: staged fails, working succeeds
			t.Run("staged_fails_working_succeeds", func(t *testing.T) {
				setupExecMocks(t) // Reset mocks for subtest
				// This still requires a stateful mock...

				// Skipping full implementation due to mock complexity needed.
				t.Skip("Skipping complex multi-call exec mock test")

				// If you had a stateful mock:
				// mockExec.Expect("git", "diff", "--cached").Returns("", "error", 1)
				// mockExec.Expect("git", "diff").Returns("?? working.txt", "", 0)
				// diff, err := getGitDiff()
				// assert.Error(t, err)
				// assert.Contains(t, err.Error(), "staged diff error")
				// assert.Equal(t, "?? working.txt", diff)
			})

		})
	}
}

func TestCommitWithGeneratedMessage(t *testing.T) {
	setupExecMocks(t) // Sets up the mock execCommand variable

	testMessage := "feat(test): add cool feature\n\nThis is the body."

	t.Run("commit success", func(t *testing.T) {
		os.Setenv("GIT_COMMIT_MOCK_EXIT_CODE", "0")
		os.Setenv("GIT_COMMIT_MOCK_STDERR", "")

		err := commitWithGeneratedMessage(testMessage)

		if err != nil {
			t.Errorf("commitWithGeneratedMessage() unexpected error = %v", err)
		}
		// Ideally, the mock helper process would capture stdin and we could verify it.
		// The current helper doesn't do that.
	})

	t.Run("commit failure", func(t *testing.T) {
		os.Setenv("GIT_COMMIT_MOCK_EXIT_CODE", "1")
		os.Setenv("GIT_COMMIT_MOCK_STDERR", "commit failed")

		err := commitWithGeneratedMessage(testMessage)

		if err == nil {
			t.Errorf("commitWithGeneratedMessage() expected an error, got nil")
		} else {
			// Check if the error message indicates failure (stdlib exit error)
			if !strings.Contains(err.Error(), "exit status 1") {
				t.Errorf("commitWithGeneratedMessage() error = %v, want error containing 'exit status 1'", err)
			}
		}
	})
}
*/ // End of commented out exec tests

func TestStoreTokens(t *testing.T) {
	setupKeyringMocks(t)

	token := &oauth2.Token{
		AccessToken:  "access-123",
		RefreshToken: "refresh-456",
		Expiry:       time.Now().Add(1 * time.Hour),
		TokenType:    "Bearer",
	}
	token = token.WithExtra(map[string]interface{}{"id_token": "id-789"})

	t.Run("store success", func(t *testing.T) {
		err := storeTokens(token)
		if err != nil {
			t.Fatalf("storeTokens() error = %v, want nil", err)
		}

		// Verify stored data
		mockKeyringMu.Lock()
		storedJSON, ok := mockKeyringStore[serviceName][userName]
		mockKeyringMu.Unlock()

		if !ok {
			t.Fatalf("Token not found in mock keyring store for service=%s, user=%s", serviceName, userName)
		}

		var storedT Tokens
		if err := json.Unmarshal([]byte(storedJSON), &storedT); err != nil {
			t.Fatalf("Failed to unmarshal stored JSON: %v", err)
		}

		if storedT.AccessToken != token.AccessToken {
			t.Errorf("Stored AccessToken mismatch: got %q, want %q", storedT.AccessToken, token.AccessToken)
		}
		if storedT.RefreshToken != token.RefreshToken {
			t.Errorf("Stored RefreshToken mismatch: got %q, want %q", storedT.RefreshToken, token.RefreshToken)
		}
		if storedT.IDToken != token.Extra("id_token") {
			t.Errorf("Stored IDToken mismatch: got %q, want %q", storedT.IDToken, token.Extra("id_token"))
		}
		if storedT.Expiry != token.Expiry.Unix() {
			t.Errorf("Stored Expiry mismatch: got %d, want %d", storedT.Expiry, token.Expiry.Unix())
		}
	})

	t.Run("store failure", func(t *testing.T) {
		mockKeyringMu.Lock()
		keyringSetError = errors.New("keyring write failed")
		mockKeyringMu.Unlock()

		err := storeTokens(token)
		if err == nil {
			t.Errorf("storeTokens() error = nil, want error")
		} else if !strings.Contains(err.Error(), "keyring write failed") {
			t.Errorf("storeTokens() error = %v, want error containing 'keyring write failed'", err)
		}
	})
}

func TestRetrieveTokens(t *testing.T) {
	setupKeyringMocks(t)

	validExpiry := time.Now().Add(1 * time.Hour).Unix()
	validTokenData := Tokens{
		AccessToken:  "access-123",
		RefreshToken: "refresh-456",
		IDToken:      "id-789",
		Expiry:       validExpiry,
	}
	validTokenJSON, _ := json.Marshal(validTokenData)

	t.Run("retrieve success", func(t *testing.T) {
		mockKeyringMu.Lock()
		mockKeyringStore[serviceName] = map[string]string{userName: string(validTokenJSON)}
		keyringGetError = nil // Ensure no error is injected
		mockKeyringMu.Unlock()

		token, err := retrieveTokens()
		if err != nil {
			t.Fatalf("retrieveTokens() error = %v, want nil", err)
		}
		if token == nil {
			t.Fatalf("retrieveTokens() token = nil, want non-nil")
		}

		if token.AccessToken != validTokenData.AccessToken {
			t.Errorf("Retrieved AccessToken mismatch: got %q, want %q", token.AccessToken, validTokenData.AccessToken)
		}
		if token.RefreshToken != validTokenData.RefreshToken {
			t.Errorf("Retrieved RefreshToken mismatch: got %q, want %q", token.RefreshToken, validTokenData.RefreshToken)
		}
		idToken, ok := token.Extra("id_token").(string)
		if !ok || idToken != validTokenData.IDToken {
			t.Errorf("Retrieved IDToken mismatch: got %q (%t), want %q", idToken, ok, validTokenData.IDToken)
		}
		if !token.Expiry.Equal(time.Unix(validExpiry, 0)) {
			t.Errorf("Retrieved Expiry mismatch: got %v, want %v", token.Expiry, time.Unix(validExpiry, 0))
		}
	})

	t.Run("retrieve not found", func(t *testing.T) {
		mockKeyringMu.Lock()
		delete(mockKeyringStore, serviceName) // Ensure service doesn't exist
		keyringGetError = keyring.ErrNotFound // Explicitly set ErrNotFound
		mockKeyringMu.Unlock()

		token, err := retrieveTokens()
		if err != nil {
			// Expecting nil error when ErrNotFound is encountered specifically
			t.Errorf("retrieveTokens() error = %v, want nil for ErrNotFound", err)
		}
		if token != nil {
			t.Errorf("retrieveTokens() token = %v, want nil for ErrNotFound", token)
		}
	})

	t.Run("retrieve other keyring error", func(t *testing.T) {
		mockKeyringMu.Lock()
		keyringGetError = errors.New("generic keyring read error")
		mockKeyringMu.Unlock()

		token, err := retrieveTokens()
		if err == nil {
			t.Errorf("retrieveTokens() error = nil, want error")
		} else if !strings.Contains(err.Error(), "generic keyring read error") {
			t.Errorf("retrieveTokens() error = %v, want error containing 'generic keyring read error'", err)
		}
		if token != nil {
			t.Errorf("retrieveTokens() token = %v, want nil on error", token)
		}
	})

	t.Run("retrieve corrupt data", func(t *testing.T) {
		mockKeyringMu.Lock()
		mockKeyringStore[serviceName] = map[string]string{userName: "this is not json"}
		keyringGetError = nil // Keyring itself succeeds
		mockKeyringMu.Unlock()

		token, err := retrieveTokens()
		if err == nil {
			t.Errorf("retrieveTokens() error = nil, want unmarshal error")
		} else if !strings.Contains(err.Error(), "failed to unmarshal stored tokens") {
			// Check for the wrapped error message
			t.Errorf("retrieveTokens() error = %v, want error containing 'failed to unmarshal stored tokens'", err)
		}
		if token != nil {
			t.Errorf("retrieveTokens() token = %v, want nil on unmarshal error", token)
		}
	})
}

// Mocking token source for refresh tests
type mockTokenSource struct {
	tokenToReturn *oauth2.Token
	errorToReturn error
}

func (m *mockTokenSource) Token() (*oauth2.Token, error) {
	return m.tokenToReturn, m.errorToReturn
}

// Mock oauth2.Config.TokenSource
var (
	originalTokenSource func(ctx context.Context, t *oauth2.Token) oauth2.TokenSource
	mockSource          *mockTokenSource
)

// We need to replace the TokenSource method for testing refreshToken
// This is tricky as it's a method on oauth2.Config.
// A simpler approach for getAuthenticatedClient is to test its logic *around* refreshToken.

func TestGetAuthenticatedClient(t *testing.T) {
	setupKeyringMocks(t)
	ctx := context.Background()
	// Dummy config - endpoint needed if refresh is attempted
	config := &oauth2.Config{
		ClientID:     "test-client",
		ClientSecret: "test-secret",
		Endpoint: oauth2.Endpoint{
			AuthURL:  "http://dummy/auth",
			TokenURL: "http://dummy/token", // Needed for refresh simulation
		},
	}

	validToken := &oauth2.Token{
		AccessToken:  "valid-access",
		RefreshToken: "valid-refresh",
		Expiry:       time.Now().Add(1 * time.Hour),
	}
	validTokenJSONBytes, _ := json.Marshal(Tokens{
		AccessToken:  validToken.AccessToken,
		RefreshToken: validToken.RefreshToken,
		Expiry:       validToken.Expiry.Unix(),
	})
	validTokenJSON := string(validTokenJSONBytes)

	expiredToken := &oauth2.Token{
		AccessToken:  "expired-access",
		RefreshToken: "expired-refresh",
		Expiry:       time.Now().Add(-1 * time.Hour), // Expired
	}
	expiredTokenJSONBytes, _ := json.Marshal(Tokens{
		AccessToken:  expiredToken.AccessToken,
		RefreshToken: expiredToken.RefreshToken,
		Expiry:       expiredToken.Expiry.Unix(),
	})
	expiredTokenJSON := string(expiredTokenJSONBytes)

	refreshedToken := &oauth2.Token{
		AccessToken:  "refreshed-access",
		RefreshToken: "refreshed-refresh", // Usually gets a new refresh token too
		Expiry:       time.Now().Add(1 * time.Hour),
	}

	t.Run("no stored token", func(t *testing.T) {
		mockKeyringMu.Lock()
		delete(mockKeyringStore, serviceName)
		keyringGetError = keyring.ErrNotFound
		mockKeyringMu.Unlock()

		client, err := getAuthenticatedClient(ctx, config)
		if err != nil {
			t.Errorf("getAuthenticatedClient() error = %v, want nil when no token found", err)
		}
		if client != http.DefaultClient {
			t.Errorf("getAuthenticatedClient() client = %T, want http.DefaultClient", client)
		}
	})

	t.Run("valid stored token", func(t *testing.T) {
		mockKeyringMu.Lock()
		mockKeyringStore[serviceName] = map[string]string{userName: validTokenJSON}
		keyringGetError = nil
		mockKeyringMu.Unlock()

		client, err := getAuthenticatedClient(ctx, config)
		if err != nil {
			t.Fatalf("getAuthenticatedClient() error = %v, want nil for valid token", err)
		}
		if client == http.DefaultClient {
			t.Errorf("getAuthenticatedClient() client is http.DefaultClient, want authenticated client")
		}
		// Verify the client is using the correct token (difficult without inspecting internals)
		// We can check that it's an *oauth2* client as a proxy
		if _, ok := client.Transport.(*oauth2.Transport); !ok {
			t.Errorf("Expected client.Transport to be *oauth2.Transport, got %T", client.Transport)
		}
	})

	t.Run("expired token refresh success", func(t *testing.T) {
		setupKeyringMocks(t) // Reset mocks, especially keyring store
		mockKeyringMu.Lock()
		mockKeyringStore[serviceName] = map[string]string{userName: expiredTokenJSON}
		keyringGetError = nil
		mockKeyringMu.Unlock()

		// --- Mocking the refresh mechanism ---
		// Replace the actual refreshToken function temporarily
		originalRefreshToken := refreshToken
		refreshToken = func(ctx context.Context, cfg *oauth2.Config, currentToken *oauth2.Token) (*oauth2.Token, error) {
			// Basic check: ensure the token passed for refresh is the expired one
			if currentToken.AccessToken != expiredToken.AccessToken {
				return nil, fmt.Errorf("mockRefreshToken called with unexpected token: %s", currentToken.AccessToken)
			}
			return refreshedToken, nil // Simulate successful refresh
		}
		t.Cleanup(func() { refreshToken = originalRefreshToken }) // Restore original
		// --- End Mocking ---

		client, err := getAuthenticatedClient(ctx, config)
		if err != nil {
			t.Fatalf("getAuthenticatedClient() error = %v, want nil on successful refresh", err)
		}
		if client == http.DefaultClient {
			t.Errorf("getAuthenticatedClient() client is http.DefaultClient, want authenticated client")
		}
		if _, ok := client.Transport.(*oauth2.Transport); !ok {
			t.Errorf("Expected client.Transport to be *oauth2.Transport, got %T", client.Transport)
		}

		// Verify the *new* token was stored
		mockKeyringMu.Lock()
		storedJSON, ok := mockKeyringStore[serviceName][userName]
		mockKeyringMu.Unlock()
		if !ok {
			t.Fatalf("New token not stored in mock keyring after refresh")
		}
		var storedT Tokens
		if err := json.Unmarshal([]byte(storedJSON), &storedT); err != nil {
			t.Fatalf("Failed to unmarshal stored JSON after refresh: %v", err)
		}
		if storedT.AccessToken != refreshedToken.AccessToken {
			t.Errorf("Stored token after refresh has wrong access token: got %q, want %q", storedT.AccessToken, refreshedToken.AccessToken)
		}
	})

	t.Run("expired token refresh failure", func(t *testing.T) {
		setupKeyringMocks(t) // Reset mocks
		mockKeyringMu.Lock()
		mockKeyringStore[serviceName] = map[string]string{userName: expiredTokenJSON}
		keyringGetError = nil
		mockKeyringMu.Unlock()

		refreshErr := errors.New("simulated refresh failure (e.g., invalid grant)")

		// --- Mocking the refresh mechanism ---
		originalRefreshToken := refreshToken
		refreshToken = func(ctx context.Context, cfg *oauth2.Config, currentToken *oauth2.Token) (*oauth2.Token, error) {
			return nil, refreshErr // Simulate failed refresh
		}
		t.Cleanup(func() { refreshToken = originalRefreshToken })
		// --- End Mocking ---

		client, err := getAuthenticatedClient(ctx, config)

		// Expecting an error *returned* by getAuthenticatedClient when refresh fails
		if err == nil {
			t.Fatalf("getAuthenticatedClient() error = nil, want error on refresh failure")
		}
		// Check if the specific refresh error is wrapped
		if !errors.Is(err, refreshErr) {
			t.Errorf("getAuthenticatedClient() error = %v, want error wrapping %q", err, refreshErr)
		}
		// Expect the default client to be returned when refresh fails
		if client != http.DefaultClient {
			t.Errorf("getAuthenticatedClient() client = %T, want http.DefaultClient on refresh failure", client)
		}

		// Optional: Verify token wasn't updated in keyring (it shouldn't be)
		mockKeyringMu.Lock()
		storedJSON, _ := mockKeyringStore[serviceName][userName]
		mockKeyringMu.Unlock()
		var storedT Tokens
		_ = json.Unmarshal([]byte(storedJSON), &storedT) // Ignore error, just check token
		if storedT.AccessToken == refreshedToken.AccessToken {
			t.Errorf("Token in keyring was updated despite refresh failure")
		}
	})

	t.Run("keyring retrieval error", func(t *testing.T) {
		retrievalErr := errors.New("simulated keyring read error")
		mockKeyringMu.Lock()
		keyringGetError = retrievalErr
		mockKeyringMu.Unlock()

		client, err := getAuthenticatedClient(ctx, config)
		if err == nil {
			t.Errorf("getAuthenticatedClient() error = nil, want error on keyring retrieval failure")
		}
		if !errors.Is(err, retrievalErr) {
			t.Errorf("getAuthenticatedClient() error = %v, want error wrapping %q", err, retrievalErr)
		}
		// Check client is nil when retrieval fails fundamentally
		// Correction: The code returns nil for the *token*, but the function returns (nil, err) for the client/error pair
		// Let's re-read the code... ah, it returns `return nil, fmt.Errorf("failed to retrieve stored tokens: %w", err)`
		// So, the client *should* be nil in this case.
		if client != nil {
			t.Errorf("getAuthenticatedClient() client = %T, want nil on fundamental retrieval failure", client)
		}
	})
}

func TestAddCommitMessageFlags(t *testing.T) {
	cmd := &cobra.Command{}
	addCommitMessageFlags(cmd)

	// Check MaxSubjectLength flag
	maxSubjectFlag := cmd.Flags().Lookup("max-subject")
	if maxSubjectFlag == nil {
		t.Fatal("Flag --max-subject not found")
	}
	if maxSubjectFlag.Name != "max-subject" {
		t.Errorf("Flag name mismatch: got %q, want %q", maxSubjectFlag.Name, "max-subject")
	}
	if maxSubjectFlag.DefValue != "50" {
		t.Errorf("Flag default value mismatch: got %q, want %q", maxSubjectFlag.DefValue, "50")
	}
	// Could also check type if needed: reflect.TypeOf(maxSubjectFlag.Value).String() == "*pflag.intValue"

	// Check Scopes flag
	scopesFlag := cmd.Flags().Lookup("scopes")
	if scopesFlag == nil {
		t.Fatal("Flag --scopes not found")
	}
	expectedScopes := []string{"feat", "fix", "docs", "style", "refactor", "test", "chore"}
	// Default value for string slice is a bit tricky to check directly, check usage string or type
	if !reflect.DeepEqual(scopesFlag.Value.(cobra.SliceValue).GetSlice(), expectedScopes) {
		// Note: This checks the *current* value after parsing defaults, not DefValue string
		t.Errorf("Flag scopes default mismatch: got %v, want %v", scopesFlag.Value.(cobra.SliceValue).GetSlice(), expectedScopes)
	}

	// Check Types flag
	typesFlag := cmd.Flags().Lookup("types")
	if typesFlag == nil {
		t.Fatal("Flag --types not found")
	}
	expectedTypes := []string{"build", "ci", "perf", "revert"}
	if !reflect.DeepEqual(typesFlag.Value.(cobra.SliceValue).GetSlice(), expectedTypes) {
		t.Errorf("Flag types default mismatch: got %v, want %v", typesFlag.Value.(cobra.SliceValue).GetSlice(), expectedTypes)
	}
}

// --- Global Variable Refactor Assumption ---
// Add this near the top of main.go for the exec tests to work as written above:
// var execCommand = exec.Command
// Then replace all calls to exec.Command in main.go with execCommand.
// ---
