# Gokta - Okta Authentication Library for Go

**Note:** This library is currently in an alpha stage. It's under active development and may be subject to changes. While Gokta is functional, it's recommended for testing and development purposes at this stage. Please use caution when integrating it into production environments.

Welcome to Gokta, a specialized library for integrating Okta authentication in Go web applications. Gokta simplifies the process of implementing OAuth 2.0 workflows, handling token management, user sessions, and secure user authentication against Okta's Identity Cloud services in web-based Go applications.

As of now, Gokta is focused on supporting the "Web Application" type in Okta's suite of application offerings. This library provides a streamlined approach to OAuth 2.0 authentication, ensuring a seamless and secure user experience. Features like JWT token parsing, configurable logging, and session management are all part of Gokta, crafted to make the integration of Okta authentication straightforward and efficient.

Looking ahead, I aim to expand Gokta's capabilities to include support for Single-Page Applications.

## Requirements

To use Gokta, ensure that your environment meets the following requirements:

1. **Go Version:** Gokta is developed with Go 1.23. It is recommended to use the same version or newer for compatibility.
2. **External Dependencies:** Gokta relies on the following Go modules:
    * github.com/gorilla/sessions v1.4.0: A session management library used for handling user sessions.
    * github.com/golang-jwt/jwt/v5 v5.2.1: Used for JSON Web Token (JWT) parsing and validation.
3. **Okta Account:** An active Okta account and an Okta application set up for the "Web Application" type. You will need to obtain the ClientID, ClientSecret, and other relevant configuration details from your Okta application.
4. **Web Application:** Gokta is currently designed for use with web applications. Ensure your project architecture aligns with this use case.

Please make sure these requirements are met before integrating Gokta into your application.

## Installation
To install Gokta in your Go project, follow these steps:

1. **Import Gokta in Your Go Module:**
    Add Gokta to your project by importing it in your Go files. For example:
    ```go
    import "github.com/zymsys/gokta"
   ```
2. **Add Gokta to Your Dependencies:**
    Run the following command in your project directory to fetch Gokta and add it to your project's dependencies:
    ```bash
    go get github.com/zymsys/gokta
   ```
    This command downloads the Gokta package along with its dependencies and updates your go.mod file.
3. **Verify Installation:**
    After installation, you can verify that Gokta is added to your project by checking your go.mod file. You should see github.com/zymsys/gokta listed under require.
4. **Update Dependencies (Optional):**
    To ensure you have the latest version of Gokta and its dependencies, you can run:
    ```bash
    go mod tidy
    ```
    This will install Gokta and make it available in your Go project. Next, you can proceed to configure Gokta as per your project's requirements.

## Configuration
To configure Gokta in your Go project, follow these steps:

1. **Create a Config Object:**
    Start by creating a config.Config object. This object holds all necessary configuration for the Gokta library. Include parameters like ClientID, ClientSecret, Issuer, etc., which you can obtain from your Okta application settings.
    ```go
    package main
   
    import (
        "github.com/zymsys/gokta"
        "github.com/zymsys/gokta/config"
    )

    func main() {
        cfg := config.Config{
            ClientID:              "YOUR_OKTA_CLIENT_ID",
            ClientSecret:          "YOUR_OKTA_CLIENT_SECRET",
            Issuer:                "YOUR_OKTA_ISSUER_URL",
            RedirectURI:           "YOUR_APPLICATION_REDIRECT_URI",
            SessionKey:            "YOUR_SESSION_ENCRYPTION_KEY",
            LoggedInURI:           "URI_AFTER_SUCCESSFUL_LOGIN",
            PostLogoutRedirectURI: "URI_AFTER_LOGOUT",
        }
    
        // Initialize Gokta with the configuration
        oktaClient := gokta.New(cfg)
        // Further setup and usage of oktaClient
    }
   ```
2. **Configure Session Store:**
    Gokta uses Gorilla Sessions for session management. The session key used in the configuration (SessionKey) should be a secure, random string. This key is crucial for encrypting and securing session data.
    If you like you can alternatively provide your own session store using Config.SessionStore.
3. **Specify Redirect URIs:**
    Ensure that the RedirectURI, LoggedInURI, and PostLogoutRedirectURI fields in your configuration are set correctly. These URIs are used during the OAuth flow and after the user logs in or logs out.
4. **Logging and HTTP Client (Optional):**
    Gokta supports custom logging and HTTP client configuration. For more detailed information on configuring and using the logging feature, refer to the Logging section below.
    ```go
    cfg.Logger = MyCustomLogger{}
    cfg.HttpClient = &http.Client{Timeout: time.Second * 30}
    ```
4. **Token Parser (Optional):**
    The default token parser can be overridden by implementing the TokenParser interface from config. This is useful if you need custom token handling logic.

After configuring Gokta, you can integrate it into your application's authentication flow.

## Usage
After configuring Gokta as described in the Configuration section, you can integrate it into your application's authentication flow. Here are some examples and explanations on how to use Gokta:

1. **Refer to Configuration:**
    For initial setup and creating an instance of OAuthClient, refer to the Configuration section above.
2. **Middleware for Protected Routes:**
    Protect your routes with Gokta middleware. This ensures that only authenticated users can access certain routes. The middleware checks for valid authentication and redirects to the login page if the user is not authenticated.
    ```go
    http.Handle("/protected-route", oktaClient.Middleware()(yourProtectedHandler))
    ```
3. **Authentication Callback Compatibility:**
    Gokta allows for flexible integration with various HTTP libraries by using a callback function to register the authentication callback route. This approach ensures compatibility across different web frameworks.
    ```go
    err := oktaClient.RegisterCallbackRoute(func(path string, handler http.Handler) {
        // Example of registering the route with your HTTP library
        http.Handle(path, handler)
    })
    if err != nil {
        log.Fatalf("Error registering callback route: %v", err)
    }
    ```
4. **User Logout:**
    Implement user logout functionality to clear the session and redirect users to the Okta logout page.
    ```go
    http.HandleFunc("/logout", oktaClient.LogoutHandler)
    ```
5. **Accessing and Using User Claims:**
    Retrieve and use user claims, like the user's email, from the session:
    ```go
    claims, err := oktaClient.GetUserClaims(request)
    if err != nil {
        // Handle error
    }
    userEmail := claims["email"].(string)
    fmt.Println("User email:", userEmail)
    ```
6. Custom User Information Handler:
    UserClaimsHandler returns user information in JSON format. An example response might look like this:
    ```json
    {
        "email": "example@email.com",
        "name": "John Doe",
        "preferred_username": "example@email.com",
        "sub": "00u1m8kb1ssZc65355d7"
    }
    ```
    To use this handler:
    ```go
    http.HandleFunc("/userinfo", oktaClient.UserClaimsHandler)
    ```
    The examples above provide a basic overview of integrating and using Gokta in your Go web applications. For more advanced usage, refer to the detailed documentation within the code.

## API Reference
This section provides a brief overview of the key types and functions available in the Gokta library:

### Types
OAuthClient:
* Represents the Okta OAuth client, managing the authentication flow and token exchanges.
* Key Methods:
  * New(config config.Config) *OAuthClient: Initializes a new OAuth client with the given configuration.
  * Middleware() func(http.Handler) http.Handler: Returns an HTTP middleware for handling authentication.
  * ExchangeCodeForToken(authorizationCode string) (*TokenResponse, error): Exchanges an authorization code for an access token and ID token.
  * RegisterCallbackRoute(registerFunc RouterFunc) error: Registers the callback route for Okta authentication.
  * GetUserClaims(r *http.Request) (jwt.MapClaims, error): Retrieves user claims from the current session.
  * UserClaimsHandler(w http.ResponseWriter, r *http.Request): A handler that returns user information as JSON.
* TokenResponse:
    * Represents the response from the token exchange with Okta.
  * Contains fields like AccessToken, IDToken, TokenType, ExpiresIn, and RefreshToken.
* TokenErrorResponse:
    * Represents an error response from the token exchange process.
  * Includes fields like ErrorCode, ErrorSummary, ErrorLink, ErrorId, and ErrorCauses.
* JwtTokenParser:
    * Implements the TokenParser interface using JWT parsing functionality.
  * Method: Parse(tokenString string, keyFunc jwt.Keyfunc, options ...jwt.ParserOption) (*jwt.Token, error)
### Functions
* **LogoutHandler(w http.ResponseWriter, r \*http.Request):**
    Handles user logout, clearing the session and redirecting to the Okta logout page.
* **LogoutURI(idToken string) (string, error):**
Generates the Okta logout URI.

This reference is a concise guide to the primary interfaces of Gokta. For more detailed information, including parameters and return types, refer to the documentation within the codebase.

## Logging
Gokta offers flexible logging capabilities, enabling the use of built-in loggers or the implementation of custom logging solutions. Here's how to use these features effectively:

### Using Built-in Loggers
Gokta includes two predefined loggers:

1. StandardLogger: Outputs log messages to standard output.
2. NoOpLogger: A no-operation logger that doesn't log any messages, which can be useful for situations where logging is not required.

To utilize one of these loggers, set it in your configuration:

```go
import (
    "github.com/zymsys/gokta/config"
    "github.com/zymsys/gokta/logging"
)

cfg := config.Config{
    // ... other configuration fields ...
    Logger: logging.StandardLogger{},
}
```
This will enable Gokta to use StandardLogger for all logging activities.

### Implementing a Custom Logger
For customized logging, you can implement the Logger interface, which includes four methods: Debug, Info, Warn, and Error. These methods accept a variadic interface{} argument, providing flexibility in message formatting.

To create a custom logger:

1. Refer to the default implementations (StandardLogger and NoOpLogger) in the logging package as a reference.
2. Model your custom logger based on these implementations, tailoring the logging behavior to fit your application's needs.

Here's a snippet showing how to set your custom logger in the configuration:

```go
cfg := config.Config{
// ... other configuration fields ...
    Logger: MyCustomLogger{}, // Replace with your custom logger
}
```
By following the approach used in the default loggers, you can create a logger that aligns seamlessly with your application's logging strategy.

## Error Handling
Gokta is designed to handle errors gracefully, ensuring that your application remains robust and reliable. Here's an overview of the error handling approach in Gokta:

### Understanding Error Responses
Gokta returns detailed error information in many cases, particularly during token exchange and authentication processes. Common error responses include:

* TokenErrorResponse: This type is returned during token exchange errors and includes fields like ErrorCode, ErrorSummary, and ErrorId. Use this information to understand the cause of the error and to inform the user or take corrective action.

### Handling Errors in Your Application
When using Gokta, you should handle errors at the points where they are likely to occur. This includes:

1. **During Token Exchange:**
* Capture and handle errors returned by ExchangeCodeForToken.
* Inspect the TokenErrorResponse for details on what went wrong.
2. During Authentication and Session Management:
* Handle errors that may occur during user authentication and session retrieval.
* Look for errors when calling methods like GetUserClaims or Middleware.
3. Custom Error Handling:
* Implement custom error handling logic in your application to manage specific error scenarios.
* Use the information provided in error responses to guide your error handling strategy.

## Contributing
Contributions to Gokta are warmly welcomed and greatly appreciated. Whether it's bug fixes, feature enhancements, or documentation improvements, here's how you can contribute:

1. Fork the Repository:
* Start by forking the Gokta repository on GitHub to your own account.
2. Clone the Forked Repository:
* Clone your fork to your local machine to start making changes.
3. Create a New Branch:
* Create a new branch for your changes. It's best to keep your changes separate from the main branch.
4. Make Your Changes:
* Implement your changes, enhancements, or fixes in your branch.
5. Test Your Changes:
* Before submitting, make sure your changes do not break any existing functionality.
* Add any necessary tests to cover the new functionality.
6. Commit and Push Your Changes:
* Commit your changes with a clear and descriptive commit message.
* Push your changes to your forked repository.
7 Submit a Pull Request:
* Go to the Gokta GitHub page and submit a pull request from your branch to the main branch of the Gokta repository.
* Provide a clear description of the changes and any relevant issue numbers.
8. Code Review:
* Once your pull request is submitted, it will be reviewed by the maintainers.
* Be open to feedback and be prepared to make some revisions if necessary.
9. Merge:
* If your pull request is approved, it will be merged into the main codebase.

By following these steps, you can contribute to the ongoing development and improvement of Gokta. We look forward to seeing your contributions!

## License
Gokta is licensed under the Apache License 2.0. The full license text is included in the LICENSE file of this repository.

## Contact/Support
If you have any questions, need support, or want to discuss Gokta, please feel free to open an issue on our GitHub repository.

Before creating a new issue, we recommend checking existing issues to see if your question or problem has already been addressed. If you find a related issue, feel free to add additional comments or insights.

For general discussions or questions, opening a new issue with a clear description will ensure that we can engage and provide assistance.
