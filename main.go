package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
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
		oidcConfig.IssuerURL = "https://token.actions.githubusercontent.com"                 // This might need adjustment, consider a well-known endpoint if available
		provider, err = oidc.NewProvider(ctx, "https://token.actions.githubusercontent.com") // Consider using a well-known endpoint if available
		if err != nil {
			log.Fatalf("Error creating GitHub provider: %v", err) // Use log.Fatalf
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
	fmt.Printf("Open this URL in your browser:\n\n%s\n\n", authURL)

	// Start a simple HTTP server to handle the callback
	http.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("state") != state {
			http.Error(w, "invalid state", http.StatusBadRequest)
			return
		}
		oauth2Token, err := config.Exchange(ctx, r.URL.Query().Get("code"))
		if err != nil {
			http.Error(w, "Failed to exchange token: "+err.Error(), http.StatusInternalServerError)
			return
		}
		rawIDToken, ok := oauth2Token.Extra("id_token").(string)
		if !ok {
			http.Error(w, "No id_token field in oauth2 token.", http.StatusInternalServerError)
			return
		}
		idToken, err := provider.Verifier(&oidc.Config{ClientID: oidcConfig.ClientID}).Verify(ctx, rawIDToken)
		if err != nil {
			http.Error(w, "Failed to verify ID Token: "+err.Error(), http.StatusInternalServerError)
			return
		}

		var claims struct {
			Email    string `json:"email"`
			Verified bool   `json:"email_verified"`
			Name     string `json:"name"`
			Login    string `json:"login"` // For GitHub
		}
		if err := idToken.Claims(&claims); err != nil {
			http.Error(w, "Failed to parse claims: "+err.Error(), http.StatusInternalServerError)
			return
		}

		fmt.Fprintf(w, "Login successful!\n")
		fmt.Fprintf(w, "Email: %s\n", claims.Email)
		fmt.Fprintf(w, "Name: %s\n", claims.Name)
		if claims.Login != "" {
			fmt.Fprintf(w, "GitHub Username: %s\n", claims.Login)
		}

		// Store the tokens securely
		if err := storeTokens(oauth2Token); err != nil {
			log.Printf("Login successful, but failed to store tokens securely: %v\n", err)
			fmt.Fprintf(w, "Login successful, but failed to store tokens securely.  Please check the logs.\n")
		} else {
			fmt.Fprintf(w, "Login successful and tokens stored securely.\n")
		}

		// Optionally, shut down the server after successful login
		go func() {
			fmt.Println("Closing callback server...")
			// You might need a more graceful shutdown mechanism in a real application
			os.Exit(0)
		}()
	})

	fmt.Printf("Listening on %s/callback...\nPress Ctrl+C to quit after successful login.\n", oidcConfig.RedirectURL)
	if err := http.ListenAndServe(":8080", nil); err != nil && err != http.ErrServerClosed {
		log.Fatalf("Error starting server: %v", err) // Use log.Fatalf
	}
}

func generateCommitMessageHandler(cmd *cobra.Command, args []string) {
	// Example of using the authenticated client (you'd adapt this for your needs)
	ctx := context.Background()
	config := &oauth2.Config{
		ClientID:     oidcConfig.ClientID,
		ClientSecret: oidcConfig.ClientSecret,
		RedirectURL:  oidcConfig.RedirectURL,
		Scopes:       oidcConfig.Scopes,
		Endpoint:     oauth2.Endpoint{}, // Endpoint will be populated later if needed
	}
	httpClient, err := getAuthenticatedClient(ctx, config)
	if err != nil {
		log.Printf("Error getting authenticated client: %v\n", err)
		fmt.Println("Proceeding without authentication for commit message generation.")
	} else {
		fmt.Println("Successfully obtained authenticated client.")
		// You can now use httpClient to make authenticated requests if needed
		_ = httpClient // To avoid "declared and not used" error for now, remove when you use it.
	}

	diff, err := getGitDiff()
	if err != nil {
		log.Printf("Error getting Git diff: %v\n", err)
		return
	}

	if len(diff) == 0 {
		fmt.Println("No changes detected.")
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
	if commitScope != "" && !contains(commitMessageConfig.ScopeKeywords, commitScope) {
		fmt.Printf("Invalid commit scope. Allowed scopes are: %s\n", strings.Join(commitMessageConfig.ScopeKeywords, ", "))
		return
	}

	// Suggest a subject based on the diff (very basic)
	suggestedSubject := generateSuggestedSubject(diff)
	fmt.Printf("Enter commit subject (max %d chars, suggested: '%s'): ", commitMessageConfig.MaxSubjectLength, suggestedSubject)
	commitSubject, _ := reader.ReadString('\n')
	commitSubject = strings.TrimSpace(commitSubject)
	if len(commitSubject) > commitMessageConfig.MaxSubjectLength {
		fmt.Printf("Commit subject exceeds the maximum length of %d characters.\n", commitMessageConfig.MaxSubjectLength)
		return
	}

	// Prompt for commit body (optional)
	fmt.Println("Enter commit body (optional, press Ctrl+D or a blank line to finish):")
	var commitBody strings.Builder
	for {
		line, err := reader.ReadString('\n')
		if err == io.EOF || line == "\n" {
			break
		}
		commitBody.WriteString(line)
	}
	commitBodyStr := strings.TrimSpace(commitBody.String())

	// Construct the commit message
	var commitMessage strings.Builder
	commitMessage.WriteString(commitType)
	if commitScope != "" {
		commitMessage.WriteString("(" + commitScope + ")")
	}
	commitMessage.WriteString(": ")
	commitMessage.WriteString(commitSubject)
	commitMessage.WriteString("\n\n")
	commitMessage.WriteString(commitBodyStr)

	fmt.Println("\nGenerated Commit Message:")
	fmt.Println(commitMessage.String())

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
	cmd := exec.Command("git", "diff", "--cached", "--staged") // Check staged changes
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	if err != nil {
		// If no staged changes, try working tree changes
		cmd = exec.Command("git", "diff")
		out.Reset()
		err = cmd.Run()
		if err != nil {
			return "", fmt.Errorf("failed to execute git diff: %w", err) // Use fmt.Errorf for wrapping
		}
	}
	return out.String(), nil
}

func generateSuggestedSubject(diff string) string {
	lines := strings.Split(diff, "\n")
	if len(lines) > 1 {
		// Try to extract a relevant line from the diff
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "+") && !strings.HasPrefix(line, "+++") {
				suggestion := strings.TrimPrefix(line, "+")
				suggestion = strings.TrimSpace(suggestion)
				if len(suggestion) > 0 {
					// Basic cleanup: remove leading/trailing whitespace and limit length
					if len(suggestion) > commitMessageConfig.MaxSubjectLength {
						return suggestion[:commitMessageConfig.MaxSubjectLength] + "..."
					}
					return suggestion
				}
			} else if strings.HasPrefix(line, "-") && !strings.HasPrefix(line, "---") {
				suggestion := strings.TrimPrefix(line, "-")
				suggestion = strings.TrimSpace(suggestion)
				if len(suggestion) > 0 {
					if len(suggestion) > commitMessageConfig.MaxSubjectLength {
						return "Remove " + suggestion[:commitMessageConfig.MaxSubjectLength-7] + "..."
					}
					return "Remove " + suggestion
				}
			} else if strings.HasPrefix(line, "diff --git") {
				parts := strings.Split(line, " ")
				if len(parts) > 2 {
					files := strings.Split(parts[2], "/")
					return fmt.Sprintf("Update %s", files[len(files)-1])
				}
			}
		}
	}
	return "Update" // Default suggestion if no clear change is found
}

func commitWithGeneratedMessage(message string) error {
	cmd := exec.Command("git", "commit", "-m", message)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func generateRandomString(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to generate random string: %w", err) // Use fmt.Errorf
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func storeTokens(tokens *oauth2.Token) error {
	t := Tokens{
		AccessToken:  tokens.AccessToken,
		IDToken:      tokens.Extra("id_token").(string),
		RefreshToken: tokens.RefreshToken,
		Expiry:       tokens.Expiry.Unix(),
	}
	tokensJSON, err := json.Marshal(t)
	if err != nil {
		return fmt.Errorf("failed to marshal tokens: %w", err)
	}
	err = keyring.Set(serviceName, userName, string(tokensJSON))
	if err != nil {
		return fmt.Errorf("failed to store tokens in keyring: %w", err)
	}
	return nil
}

func retrieveTokens() (*oauth2.Token, error) {
	tokensJSON, err := keyring.Get(serviceName, userName)
	if err != nil {
		if err == keyring.ErrNoSecret {
			return nil, nil // No tokens stored yet, not an error
		}
		return nil, fmt.Errorf("failed to retrieve tokens from keyring: %w", err)
	}
	var t Tokens
	if err := json.Unmarshal([]byte(tokensJSON), &t); err != nil {
		return nil, fmt.Errorf("failed to unmarshal tokens: %w", err)
	}
	return &oauth2.Token{
		AccessToken:  t.AccessToken,
		RefreshToken: t.RefreshToken,
		Expiry:       time.Unix(t.Expiry, 0),
		TokenType:    "Bearer", // Assuming Bearer token
	}, nil
}

func refreshToken(ctx context.Context, config *oauth2.Config, refreshToken string) (*oauth2.Token, error) {
	src := config.TokenSource(ctx, &oauth2.Token{RefreshToken: refreshToken})
	newToken, err := src.Token()
	if err != nil {
		return nil, fmt.Errorf("failed to refresh token: %w", err)
	}
	return newToken, nil
}

func getAuthenticatedClient(ctx context.Context, config *oauth2.Config) (*http.Client, error) {
	storedToken, err := retrieveTokens()
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve stored tokens: %w", err) // Wrap the error
	}

	if storedToken == nil {
		return http.DefaultClient, nil // No stored token, return default client (not authenticated)
	}

	if time.Until(storedToken.Expiry) < 5*time.Minute { // Check if token is about to expire
		newToken, err := refreshToken(ctx, config, storedToken.RefreshToken)
		if err != nil {
			// Handle refresh failure (user might need to log in again)
			log.Printf("Failed to refresh token: %v\n", err) // Log the error
			// Return the default client, and let the user know.
			return http.DefaultClient, nil
		}
		if err := storeTokens(newToken); err != nil {
			log.Printf("Error storing refreshed tokens: %v\n", err)
			// Consider error handling
		}
		return config.Client(ctx, newToken), nil
	}

	return config.Client(ctx, storedToken), nil
}

// Helper function to open a URL in the browser
func openBrowser(url string) error {
	var err error
	switch runtime.GOOS {
	case "linux":
		err = exec.Command("xdg-open", url).Start()
	case "windows":
		err = exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
	case "darwin":
		err = exec.Command("open", url).Start()
	default:
		err = fmt.Errorf("unsupported platform")
	}
	return err
}
