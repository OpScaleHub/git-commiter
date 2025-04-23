package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors" // Ensure errors package is imported
	"fmt"
	"io"
	"log" // Changed from "fmt" to "log" for more robust error handling
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/spf13/cobra"
	"github.com/zalando/go-keyring"
	"golang.org/x/oauth2"
)

const serviceName = "git-helper-oidc"
const userName = "default" // Could be made more dynamic based on user info

// OIDC Configuration
type OIDCConfig struct {
	ClientID     string
	ClientSecret string
	RedirectURL  string
	IssuerURL    string
	Provider     string // "google" or "github"
	Scopes       []string
}

// Git Commit Message Generation Configuration
type CommitMessageConfig struct {
	MaxSubjectLength int
	ScopeKeywords    []string
	TypeKeywords     []string
}

// Tokens struct to store OIDC related tokens
type Tokens struct {
	AccessToken  string `json:"access_token"`
	IDToken      string `json:"id_token"`
	RefreshToken string `json:"refresh_token"`
	Expiry       int64  `json:"expiry"` // Unix timestamp
}

// Global Configurations
var (
	oidcConfig          OIDCConfig
	commitMessageConfig CommitMessageConfig
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "git-helper",
		Short: "A CLI tool for OIDC login and generating Git commit messages.",
	}

	loginCmd := &cobra.Command{
		Use:   "login",
		Short: "Perform OIDC login with Gmail or GitHub.",
		Run:   loginHandler,
	}

	generateCommitMessageCmd := &cobra.Command{
		Use:   "commit-msg",
		Short: "Generate a meaningful Git commit message based on diff.",
		Run:   generateCommitMessageHandler,
	}

	// OIDC Login Flags
	loginCmd.Flags().StringVar(&oidcConfig.Provider, "provider", "", "OIDC provider (google or github) [required]")
	loginCmd.Flags().StringVar(&oidcConfig.ClientID, "client-id", "", "OIDC Client ID [required]")
	loginCmd.Flags().StringVar(&oidcConfig.ClientSecret, "client-secret", "", "OIDC Client Secret [required]")
	loginCmd.Flags().StringVar(&oidcConfig.RedirectURL, "redirect-url", "http://localhost:8080/callback", "OIDC Redirect URL")
	loginCmd.Flags().StringSliceVar(&oidcConfig.Scopes, "scopes", []string{"openid", "profile", "email", "offline_access"}, "OIDC scopes to request") // Include offline_access

	// Commit Message Flags
	addCommitMessageFlags(generateCommitMessageCmd)

	rootCmd.AddCommand(loginCmd)
	rootCmd.AddCommand(generateCommitMessageCmd)

	if err := rootCmd.Execute(); err != nil {
		log.Fatalf("Error executing root command: %v", err) // Use log.Fatalf for critical errors
	}
}

func addCommitMessageFlags(cmd *cobra.Command) {
	cmd.Flags().IntVar(&commitMessageConfig.MaxSubjectLength, "max-subject", 50, "Maximum length of the commit subject.")
	cmd.Flags().StringSliceVar(&commitMessageConfig.ScopeKeywords, "scopes", []string{"feat", "fix", "docs", "style", "refactor", "test", "chore"}, "Comma-separated list of allowed commit scopes.")
	cmd.Flags().StringSliceVar(&commitMessageConfig.TypeKeywords, "types", []string{"build", "ci", "perf", "revert"}, "Comma-separated list of allowed commit types.")
}

func loginHandler(cmd *cobra.Command, args []string) {
	if oidcConfig.Provider == "" || oidcConfig.ClientID == "" || oidcConfig.ClientSecret == "" {
		log.Println("Error: --provider, --client-id, and --client-secret are required for login.")
		os.Exit(1)
	}

	ctx := context.Background()
	var provider *oidc.Provider
	var err error

	switch strings.ToLower(oidcConfig.Provider) {
	case "google":
		oidcConfig.IssuerURL = "https://accounts.google.com"
		provider, err = oidc.NewProvider(ctx, oidcConfig.IssuerURL)
		if err != nil {
			log.Fatalf("Error creating Google provider: %v", err) // Use log.Fatalf
		}
	case "github":
		// Note: GitHub OIDC for Actions uses a specific issuer URL format.
		// For user login via OAuth/OIDC, the endpoints are different.
		// This might need adjustment depending on the exact GitHub OIDC flow you intend.
		// For standard GitHub OAuth2/OIDC login, the endpoints are typically:
		// Issuer: https://github.com/login/oauth
		// Auth:   https://github.com/login/oauth/authorize
		// Token:  https://github.com/login/oauth/access_token
		// UserInfo: https://api.github.com/user
		// Using a generic OIDC provider setup might require more configuration or a dedicated library.
		// Let's assume a standard OIDC setup for now, but be aware this might need changes.
		oidcConfig.IssuerURL = "https://github.com" // Placeholder - Adjust if using a specific GitHub OIDC endpoint
		provider, err = oidc.NewProvider(ctx, oidcConfig.IssuerURL)
		if err != nil {
			log.Fatalf("Error creating GitHub provider (check IssuerURL): %v", err) // Use log.Fatalf
		}
	default:
		log.Printf("Error: Unsupported provider '%s'. Use 'google' or 'github'.\n", oidcConfig.Provider)
		os.Exit(1)
	}

	config := oauth2.Config{
		ClientID:     oidcConfig.ClientID,
		ClientSecret: oidcConfig.ClientSecret,
		RedirectURL:  oidcConfig.RedirectURL,
		Scopes:       oidcConfig.Scopes,
		Endpoint:     provider.Endpoint(),
	}

	state, err := generateRandomString(32)
	if err != nil {
		log.Fatalf("Error generating state: %v", err) // Use log.Fatalf
	}

	authURL := config.AuthCodeURL(state)
	fmt.Printf("Attempting to open your browser for authentication...\n")
	err = openBrowser(authURL)
	if err != nil {
		log.Printf("Could not open browser automatically: %v\nPlease open this URL manually:\n\n%s\n\n", err, authURL)
	} else {
		fmt.Printf("If your browser didn't open, please open this URL:\n\n%s\n\n", authURL)
	}

	// Start a simple HTTP server to handle the callback
	server := &http.Server{Addr: ":8080"} // Use a specific port, e.g., :8080 based on RedirectURL
	http.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("state") != state {
			http.Error(w, "invalid state", http.StatusBadRequest)
			log.Println("Error: Invalid state received in callback")
			return
		}
		oauth2Token, err := config.Exchange(ctx, r.URL.Query().Get("code"))
		if err != nil {
			http.Error(w, "Failed to exchange token: "+err.Error(), http.StatusInternalServerError)
			log.Printf("Error exchanging token: %v\n", err)
			return
		}
		rawIDToken, ok := oauth2Token.Extra("id_token").(string)
		if !ok {
			http.Error(w, "No id_token field in oauth2 token.", http.StatusInternalServerError)
			log.Println("Error: No id_token found in token response")
			return
		}
		idToken, err := provider.Verifier(&oidc.Config{ClientID: oidcConfig.ClientID}).Verify(ctx, rawIDToken)
		if err != nil {
			http.Error(w, "Failed to verify ID Token: "+err.Error(), http.StatusInternalServerError)
			log.Printf("Error verifying ID token: %v\n", err)
			return
		}

		var claims struct {
			Email             string `json:"email"`
			Verified          bool   `json:"email_verified"`
			Name              string `json:"name"`
			Login             string `json:"login"`              // For GitHub username (often in 'preferred_username' or 'login')
			PreferredUsername string `json:"preferred_username"` // Another common claim for username
		}
		if err := idToken.Claims(&claims); err != nil {
			http.Error(w, "Failed to parse claims: "+err.Error(), http.StatusInternalServerError)
			log.Printf("Error parsing claims: %v\n", err)
			return
		}

		// Store the tokens securely
		if err := storeTokens(oauth2Token); err != nil {
			log.Printf("Login successful, but failed to store tokens securely: %v\n", err)
			fmt.Fprintf(w, "Login successful, but failed to store tokens securely. Please check the logs.\n")
		} else {
			fmt.Fprintf(w, "Login successful and tokens stored securely.\n")
			log.Println("Login successful and tokens stored.")
		}

		fmt.Fprintf(w, "You can close this window now.\n")

		// Optionally, shut down the server after successful login
		go func() {
			log.Println("Shutting down callback server...")
			// Give a small delay for the response to be sent
			time.Sleep(1 * time.Second)
			if err := server.Shutdown(context.Background()); err != nil {
				log.Printf("Error shutting down server: %v", err)
			}
		}()
	})

	// Extract host:port from RedirectURL for ListenAndServe
	// This is basic, might need improvement for different URL formats
	listenAddr := ":8080" // Default
	if parts := strings.Split(oidcConfig.RedirectURL, ":"); len(parts) == 3 {
		if portParts := strings.Split(parts[2], "/"); len(portParts) > 0 {
			listenAddr = ":" + portParts[0]
		}
	} else if strings.HasPrefix(oidcConfig.RedirectURL, "http://localhost/") {
		listenAddr = ":80" // Default HTTP port
	}

	fmt.Printf("Listening on %s for callback...\n", listenAddr)
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("Error starting server on %s: %v", listenAddr, err) // Use log.Fatalf
	}
	log.Println("Callback server finished.") // Will be printed after Shutdown completes
}

func generateCommitMessageHandler(cmd *cobra.Command, args []string) {
	// Example of using the authenticated client (you'd adapt this for your needs)
	ctx := context.Background()

	// We need provider info to potentially refresh tokens, retrieve it if possible
	// This part assumes login might have happened previously. A more robust approach
	// might store the provider info alongside the token or require it again.
	// For now, we'll try to get an authenticated client without full provider setup.
	// This might fail during token refresh if endpoint info isn't available.
	tempOAuthConfig := &oauth2.Config{
		ClientID:     oidcConfig.ClientID,     // Might be empty if not provided via flags
		ClientSecret: oidcConfig.ClientSecret, // Might be empty
		RedirectURL:  oidcConfig.RedirectURL,  // Might be empty
		Scopes:       oidcConfig.Scopes,       // Might be default
		// Endpoint needs to be set for refresh, which we don't have here easily
		// without re-running the provider discovery logic from loginHandler.
		// This highlights a potential design issue: commit-msg might need access
		// to the provider's endpoint info stored after login.
	}

	httpClient, err := getAuthenticatedClient(ctx, tempOAuthConfig) // Pass potentially incomplete config
	if err != nil {
		log.Printf("Warning: Could not retrieve or refresh authentication tokens: %v\n", err)
		fmt.Println("Proceeding without authentication for commit message generation.")
		httpClient = http.DefaultClient // Fallback to default client
	} else if httpClient != http.DefaultClient {
		fmt.Println("Using authenticated client.")
		// You can now use httpClient to make authenticated requests if needed
		// e.g., fetch issue details from GitHub/Jira based on branch name
	} else {
		fmt.Println("Proceeding without authentication (no tokens found or refresh needed but failed).")
	}
	_ = httpClient // Avoid unused variable error if not used later

	diff, err := getGitDiff()
	if err != nil {
		// getGitDiff now returns an error if commands fail, handle it here
		log.Printf("Error getting Git diff: %v\n", err)
		fmt.Println("Could not get Git diff. Please ensure you are in a Git repository and 'git' command is available.")
		return // Stop if we can't get the diff
	}

	if len(diff) == 0 {
		fmt.Println("No changes detected (checked staged and working directory).")
		return
	}

	reader := bufio.NewReader(os.Stdin)

	// Prompt for commit type
	fmt.Printf("Enter commit type (%s): ", strings.Join(commitMessageConfig.TypeKeywords, "|"))
	commitType, _ := reader.ReadString('\n')
	commitType = strings.TrimSpace(strings.ToLower(commitType))
	if !contains(commitMessageConfig.TypeKeywords, commitType) {
		fmt.Printf("Invalid commit type. Allowed types are: %s\n", strings.Join(commitMessageConfig.TypeKeywords, ", "))
		return
	}

	// Prompt for commit scope (optional)
	fmt.Printf("Enter commit scope (optional, e.g., component, module, leave empty if none) (%s): ", strings.Join(commitMessageConfig.ScopeKeywords, "|"))
	commitScope, _ := reader.ReadString('\n')
	commitScope = strings.TrimSpace(commitScope)
	// Allow empty scope, no validation needed if empty
	if commitScope != "" && !contains(commitMessageConfig.ScopeKeywords, commitScope) {
		fmt.Printf("Invalid commit scope. Allowed scopes are: %s\n", strings.Join(commitMessageConfig.ScopeKeywords, ", "))
		return
	}

	// Suggest a subject based on the diff (very basic)
	suggestedSubject := generateSuggestedSubject(diff)
	fmt.Printf("Enter commit subject (max %d chars, suggested: '%s'): ", commitMessageConfig.MaxSubjectLength, suggestedSubject)
	commitSubject, _ := reader.ReadString('\n')
	commitSubject = strings.TrimSpace(commitSubject)
	if commitSubject == "" {
		fmt.Println("Commit subject cannot be empty.")
		return
	}
	if len(commitSubject) > commitMessageConfig.MaxSubjectLength {
		fmt.Printf("Commit subject exceeds the maximum length of %d characters.\n", commitMessageConfig.MaxSubjectLength)
		return
	}

	// Prompt for commit body (optional)
	fmt.Println("Enter commit body (optional, press Enter on a blank line or Ctrl+D to finish):")
	var commitBody strings.Builder
	for {
		line, err := reader.ReadString('\n')
		// Trim space to check for truly blank line
		trimmedLine := strings.TrimSpace(line)
		if err == io.EOF || trimmedLine == "" {
			break // Exit on EOF or blank line
		}
		commitBody.WriteString(line) // Keep original newline
	}
	commitBodyStr := strings.TrimSpace(commitBody.String()) // Trim final result

	// Construct the commit message (Conventional Commits format)
	var commitMessage strings.Builder
	commitMessage.WriteString(commitType)
	if commitScope != "" {
		commitMessage.WriteString("(" + commitScope + ")")
	}
	commitMessage.WriteString(": ")
	commitMessage.WriteString(commitSubject) // Subject is mandatory

	if commitBodyStr != "" {
		commitMessage.WriteString("\n\n") // Ensure blank line between subject and body
		commitMessage.WriteString(commitBodyStr)
	}

	fmt.Println("\n--- Generated Commit Message ---")
	fmt.Println(commitMessage.String())
	fmt.Println("-------------------------------")

	// Optionally, ask if the user wants to apply this message to a commit
	fmt.Print("\nDo you want to use this message for a Git commit? (y/N): ")
	response, _ := reader.ReadString('\n')
	response = strings.TrimSpace(strings.ToLower(response))
	if response == "y" {
		err := commitWithGeneratedMessage(commitMessage.String())
		if err != nil {
			log.Printf("Error during Git commit: %v\n", err)
		} else {
			fmt.Println("Git commit successful.")
		}
	} else {
		fmt.Println("Commit message not applied.")
	}
}

func getGitDiff() (string, error) {
	var stagedDiff, workingDiff string
	var stagedErrStr, workingErrStr string
	var finalErr error // To accumulate errors

	// Check staged changes first
	cmdStaged := exec.Command("git", "diff", "--cached")
	var outStaged bytes.Buffer
	var stderrStaged bytes.Buffer
	cmdStaged.Stdout = &outStaged
	cmdStaged.Stderr = &stderrStaged
	stagedErr := cmdStaged.Run() // Use a separate error variable
	stagedDiff = outStaged.String()
	stagedErrStr = stderrStaged.String()
	if stagedErr != nil {
		// Log or store the error, decide later if it's fatal
		log.Printf("Warning: 'git diff --cached' failed: %v, stderr: %s", stagedErr, stagedErrStr)
		finalErr = fmt.Errorf("staged diff error: %w", stagedErr) // Start accumulating
	}

	// Check working directory changes
	cmdWorking := exec.Command("git", "diff")
	var outWorking bytes.Buffer
	var stderrWorking bytes.Buffer
	cmdWorking.Stdout = &outWorking
	cmdWorking.Stderr = &stderrWorking
	workingErr := cmdWorking.Run() // Use another separate error variable
	workingDiff = outWorking.String()
	workingErrStr = stderrWorking.String()
	if workingErr != nil {
		log.Printf("Warning: 'git diff' failed: %v, stderr: %s", workingErr, workingErrStr)
		if finalErr != nil {
			// Combine errors if both failed
			finalErr = fmt.Errorf("working dir diff error: %v (also encountered: %w)", workingErr, finalErr)
		} else {
			finalErr = fmt.Errorf("working dir diff error: %w", workingErr)
		}
	}

	// Combine the diffs
	combinedDiff := strings.TrimSpace(stagedDiff + "\n" + workingDiff)

	// Return the combined diff. If there were errors, return the accumulated error.
	// This is slightly different from the original logic which only errored if diff was empty AND stderr was present.
	// Now, we return an error if *any* git command failed.
	return combinedDiff, finalErr
}

func generateSuggestedSubject(diff string) string {
	lines := strings.Split(diff, "\n")
	var firstMeaningfulChange string

	for _, line := range lines {
		trimmedLine := strings.TrimSpace(line)
		// Look for added/modified lines first
		if strings.HasPrefix(trimmedLine, "+") && !strings.HasPrefix(trimmedLine, "+++") {
			suggestion := strings.TrimSpace(strings.TrimPrefix(trimmedLine, "+"))
			if len(suggestion) > 0 {
				firstMeaningfulChange = suggestion
				break // Found a good candidate
			}
		}
	}

	// If no added line found, look for deleted lines
	if firstMeaningfulChange == "" {
		for _, line := range lines {
			trimmedLine := strings.TrimSpace(line)
			if strings.HasPrefix(trimmedLine, "-") && !strings.HasPrefix(trimmedLine, "---") {
				suggestion := strings.TrimSpace(strings.TrimPrefix(trimmedLine, "-"))
				if len(suggestion) > 0 {
					firstMeaningfulChange = "Remove " + suggestion // Prefix with "Remove"
					break
				}
			}
		}
	}

	// If still nothing, try to get a filename
	if firstMeaningfulChange == "" {
		for _, line := range lines {
			if strings.HasPrefix(line, "diff --git a/") {
				parts := strings.Split(line, " ")
				if len(parts) >= 3 {
					// Extract filename after a/
					filePath := strings.TrimPrefix(parts[2], "a/")
					fileParts := strings.Split(filePath, "/")
					fileName := fileParts[len(fileParts)-1]
					firstMeaningfulChange = fmt.Sprintf("Update %s", fileName)
					break
				}
			}
		}
	}

	// Final fallback and length limiting
	if firstMeaningfulChange == "" {
		firstMeaningfulChange = "Update code" // Generic fallback
	}

	if len(firstMeaningfulChange) > commitMessageConfig.MaxSubjectLength {
		// Try to cut at word boundary
		if pos := strings.LastIndex(firstMeaningfulChange[:commitMessageConfig.MaxSubjectLength-3], " "); pos != -1 {
			return firstMeaningfulChange[:pos] + "..."
		}
		// Force cut if no space found
		return firstMeaningfulChange[:commitMessageConfig.MaxSubjectLength-3] + "..."
	}

	return firstMeaningfulChange
}

func commitWithGeneratedMessage(message string) error {
	// Use -F - to read the message from stdin, handles multi-line messages correctly
	cmd := exec.Command("git", "commit", "-F", "-")
	cmd.Stdin = strings.NewReader(message) // Pipe the message to stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func generateRandomString(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to generate random string: %w", err) // Use fmt.Errorf
	}
	// Use RawURLEncoding to avoid padding characters ('=') which might cause issues in URLs
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func contains(slice []string, item string) bool {
	itemLower := strings.ToLower(item) // Case-insensitive check
	for _, s := range slice {
		if strings.ToLower(s) == itemLower {
			return true
		}
	}
	return false
}

func storeTokens(tokens *oauth2.Token) error {
	// Ensure RefreshToken is included if present
	idTokenStr := ""
	if idToken, ok := tokens.Extra("id_token").(string); ok {
		idTokenStr = idToken
	}

	t := Tokens{
		AccessToken:  tokens.AccessToken,
		IDToken:      idTokenStr,
		RefreshToken: tokens.RefreshToken,
		Expiry:       tokens.Expiry.Unix(),
	}
	tokensJSON, err := json.Marshal(t)
	if err != nil {
		return fmt.Errorf("failed to marshal tokens: %w", err)
	}
	err = keyring.Set(serviceName, userName, string(tokensJSON))
	if err != nil {
		// Provide more context about the keyring error if possible
		return fmt.Errorf("failed to store tokens in keyring (service=%s, user=%s): %w", serviceName, userName, err)
	}
	log.Printf("Tokens stored successfully in keyring for service=%s, user=%s", serviceName, userName)
	return nil
}

func retrieveTokens() (*oauth2.Token, error) {
	tokensJSON, err := keyring.Get(serviceName, userName)
	if err != nil {
		// *** THE FIX IS HERE (already present in your code) ***
		// Use errors.Is() for robust error checking, handles wrapped errors.
		if errors.Is(err, keyring.ErrNotFound) {
			log.Printf("No tokens found in keyring for service=%s, user=%s. User needs to login.", serviceName, userName)
			return nil, nil // No tokens stored yet, not an application error
		}
		// Log the actual error for debugging
		log.Printf("Error retrieving tokens from keyring (service=%s, user=%s): %v", serviceName, userName, err)
		return nil, fmt.Errorf("failed to retrieve tokens from keyring: %w", err)
	}

	var t Tokens
	if err := json.Unmarshal([]byte(tokensJSON), &t); err != nil {
		// If unmarshalling fails, the stored data might be corrupt.
		log.Printf("Failed to unmarshal stored tokens for service=%s, user=%s. Data might be corrupt. Error: %v", serviceName, userName, err)
		// Consider deleting the corrupt entry?
		// keyring.Delete(serviceName, userName)
		return nil, fmt.Errorf("failed to unmarshal stored tokens: %w", err)
	}

	// Reconstruct the oauth2.Token
	token := &oauth2.Token{
		AccessToken:  t.AccessToken,
		RefreshToken: t.RefreshToken,
		Expiry:       time.Unix(t.Expiry, 0),
		TokenType:    "Bearer", // Assuming Bearer token type
	}

	// Add ID token back if it exists
	if t.IDToken != "" {
		token = token.WithExtra(map[string]interface{}{
			"id_token": t.IDToken,
		})
	}

	log.Printf("Tokens retrieved successfully from keyring for service=%s, user=%s", serviceName, userName)
	return token, nil
}

func refreshToken(ctx context.Context, config *oauth2.Config, currentToken *oauth2.Token) (*oauth2.Token, error) {
	if currentToken.RefreshToken == "" {
		return nil, errors.New("no refresh token available to refresh")
	}
	// Check if the config has endpoint info needed for refresh
	if config.Endpoint.AuthURL == "" || config.Endpoint.TokenURL == "" {
		// This happens if getAuthenticatedClient was called without full provider info
		// We need to re-discover the provider endpoint based on stored info or config
		log.Println("Attempting to refresh token, but OIDC provider endpoint info is missing. Re-discovering...")
		// TODO: Implement logic to load provider IssuerURL (maybe store it with token?)
		// and re-run oidc.NewProvider(ctx, issuerURL) to get the endpoint.
		// For now, return an error indicating login is required.
		return nil, errors.New("cannot refresh token: OIDC provider endpoint info missing, please login again")

		// --- Example of how re-discovery might look (requires storing IssuerURL) ---
		// storedIssuerURL := "https://accounts.google.com" // Load this from somewhere
		// provider, err := oidc.NewProvider(ctx, storedIssuerURL)
		// if err != nil {
		// 	 return nil, fmt.Errorf("failed to re-discover provider for refresh: %w", err)
		// }
		// config.Endpoint = provider.Endpoint()
		// log.Println("Re-discovered provider endpoint for token refresh.")
		// --- End Example ---
	}

	src := config.TokenSource(ctx, currentToken) // Use currentToken which includes RefreshToken
	newToken, err := src.Token()                 // This performs the refresh using the RefreshToken
	if err != nil {
		// Check for specific OAuth2 errors like invalid_grant (refresh token expired/revoked)
		if oauthErr, ok := err.(*oauth2.RetrieveError); ok {
			if strings.Contains(string(oauthErr.Body), "invalid_grant") {
				log.Println("Refresh token is invalid or expired. User needs to login again.")
				// Optionally delete the invalid stored token here
				// errDel := keyring.Delete(serviceName, userName)
				// if errDel != nil && !errors.Is(errDel, keyring.ErrNotFound) { // Use errors.Is if uncommenting
				//  log.Printf("Failed to delete invalid token from keyring: %v", errDel)
				// }
				return nil, fmt.Errorf("refresh token invalid, please login again: %w", err)
			}
		}
		return nil, fmt.Errorf("failed to refresh token: %w", err)
	}
	log.Println("Token refreshed successfully.")
	return newToken, nil
}

func getAuthenticatedClient(ctx context.Context, config *oauth2.Config) (*http.Client, error) {
	storedToken, err := retrieveTokens()
	if err != nil {
		// retrieveTokens already logs details, just wrap the error for the caller
		return nil, fmt.Errorf("failed to retrieve stored tokens: %w", err)
	}

	if storedToken == nil {
		log.Println("No stored token found. Returning default HTTP client.")
		return http.DefaultClient, nil // No stored token, return default client (not authenticated)
	}

	// Check if token is expired or close to expiring (e.g., within 5 minutes)
	// Use a small buffer to avoid using a token right before it expires.
	if !storedToken.Valid() || time.Until(storedToken.Expiry) < 5*time.Minute {
		log.Printf("Stored token is expired or nearing expiry (valid: %t, expires in: %s). Attempting refresh...", storedToken.Valid(), time.Until(storedToken.Expiry).Round(time.Second))
		newToken, refreshErr := refreshToken(ctx, config, storedToken)
		if refreshErr != nil {
			// Handle refresh failure (user might need to log in again)
			log.Printf("Failed to refresh token: %v. Returning default HTTP client.", refreshErr)
			// Decide if we should delete the expired/unrefreshable token
			// errDel := keyring.Delete(serviceName, userName)
			// if errDel != nil {
			//	 log.Printf("Failed to delete invalid token from keyring: %v", errDel)
			// }
			// Return default client, indicating authentication is lost.
			// The error from refreshToken is returned to signal the issue.
			return http.DefaultClient, fmt.Errorf("token refresh failed: %w", refreshErr)
		}

		// Refresh succeeded, store the new token
		if storeErr := storeTokens(newToken); storeErr != nil {
			// Log the error, but proceed with the new token for this session
			log.Printf("Successfully refreshed token, but failed to store the new token: %v", storeErr)
		} else {
			log.Println("Successfully refreshed and stored new token.")
		}
		// Return client authenticated with the NEW token
		return config.Client(ctx, newToken), nil
	}

	// Stored token is valid and not expiring soon
	log.Println("Using valid stored token.")
	return config.Client(ctx, storedToken), nil
}

// Helper function to open a URL in the browser
func openBrowser(url string) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "linux":
		// Try common Linux openers
		_, err := exec.LookPath("xdg-open")
		if err == nil {
			cmd = exec.Command("xdg-open", url)
		} else {
			_, err = exec.LookPath("gnome-open")
			if err == nil {
				cmd = exec.Command("gnome-open", url)
			} else {
				_, err = exec.LookPath("kde-open")
				if err == nil {
					cmd = exec.Command("kde-open", url)
				} else {
					return fmt.Errorf("could not find xdg-open, gnome-open, or kde-open")
				}
			}
		}
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	case "darwin":
		cmd = exec.Command("open", url)
	default:
		return fmt.Errorf("unsupported platform: %s", runtime.GOOS)
	}
	// Use Start() not Run() to open asynchronously and not block the CLI
	return cmd.Start()
}

// Note: The above code is a simplified version of the original code.
