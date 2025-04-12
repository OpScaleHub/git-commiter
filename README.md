# Gitter

**Explanation and Structure:**

1.  **`package main`**: The entry point of the Go application.
2.  **`import`**: Necessary Go packages for various functionalities like input/output, HTTP, OIDC, command-line interface, etc.
3.  **`OIDCConfig` and `CommitMessageConfig`**: Structs to hold configuration parameters for OIDC login and commit message generation.
4.  **Global Variables**: `oidcConfig` and `commitMessageConfig` store the parsed configuration.
5.  **`main()`**:
    * Initializes the root Cobra command `git-helper`.
    * Defines two subcommands: `login` and `commit-msg`.
    * Adds flags to the `login` command for OIDC configuration.
    * Adds flags to the `commit-msg` command for commit message generation.
    * Executes the Cobra command, handling any errors.
6.  **`addCommitMessageFlags(cmd *cobra.Command)`**: Defines the flags specific to the `commit-msg` subcommand.
7.  **`loginHandler(cmd *cobra.Command, args []string)`**:
    * Checks for required OIDC flags.
    * Sets the `IssuerURL` based on the `--provider` (Google or GitHub). **Note:** The GitHub OIDC discovery might be different; you might need to adjust the `IssuerURL` or use a specific endpoint.
    * Creates an OIDC provider instance.
    * Configures the OAuth2 configuration with Client ID, Secret, Redirect URL, Scopes, and Endpoint.
    * Generates a random state for security.
    * Constructs the authorization URL.
    * Prints the URL for the user to open in their browser.
    * Starts a simple HTTP server on `http://localhost:8080/callback` to handle the OIDC callback.
    * In the callback handler:
        * Verifies the state.
        * Exchanges the authorization code for an access token and ID token.
        * Verifies the ID token.
