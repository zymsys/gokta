package gokta

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/sessions"
	"github.com/zymsys/gokta/config"
	"github.com/zymsys/gokta/internal/jwks"
	"github.com/zymsys/gokta/logging"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Exported types
type Config = config.Config
type Logger = logging.Logger
type StandardLogger = logging.StandardLogger
type NoOpLogger = logging.NoOpLogger

// OAuthClient represents the Okta OAuth client.
type OAuthClient struct {
	Config       config.Config
	SessionStore sessions.Store
	jwksClient   *jwks.JWKSClient
}

// TokenResponse represents the response from the token exchange
type TokenResponse struct {
	AccessToken    string    `json:"access_token"`
	IDToken        string    `json:"id_token"`
	TokenType      string    `json:"token_type"`
	ExpiresIn      int       `json:"expires_in"`
	RefreshToken   string    `json:"refresh_token,omitempty"`
	ExpirationTime time.Time `json:"expiration_time"`
}

type TokenErrorResponse struct {
	ErrorCode    string   `json:"errorCode"`
	ErrorSummary string   `json:"errorSummary"`
	ErrorLink    string   `json:"errorLink"`
	ErrorId      string   `json:"errorId"`
	ErrorCauses  []string `json:"errorCauses"`
}

type JwtTokenParser struct{}

// Parse implements the TokenParser interface using jwt.Parse.
func (JwtTokenParser) Parse(tokenString string, keyFunc jwt.Keyfunc, options ...jwt.ParserOption) (*jwt.Token, error) {
	return jwt.Parse(tokenString, keyFunc, options...)
}

const sessionName = "okta-auth-session"

// RouterFunc is a function type that satisfies the Router interface by allowing
// the registration of a new route.
type RouterFunc func(path string, handler http.Handler)

// Handle allows RouterFunc to satisfy the Router interface.
func (f RouterFunc) Handle(path string, handler http.Handler) {
	f(path, handler)
}

// generateState creates a new random state for each authentication request
func generateState() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

// New creates a new OAuthClient with the provided configurations.
func New(config config.Config) *OAuthClient {
	if config.Logger == nil {
		config.Logger = logging.NoOpLogger{}
	}

	if config.HttpClient == nil {
		config.HttpClient = &http.Client{
			// You can set default timeout or other settings here
			Timeout: time.Second * 30,
		}
	}

	store := sessions.NewCookieStore([]byte(config.SessionKey))

	store.Options = &sessions.Options{
		Path:     "/",                  // The path for the cookie. '/' means it's valid for all subpaths.
		MaxAge:   86400 * 7,            // MaxAge=0 means no 'Max-Age' attribute specified. MaxAge<0 means delete cookie now.
		HttpOnly: true,                 // HttpOnly means the cookie is not accessible to JavaScript.
		Secure:   true,                 // Secure means the cookie will be sent only over HTTPS.
		SameSite: http.SameSiteLaxMode, // SameSite prevents the browser from sending this cookie along with cross-site requests.
	}

	if strings.HasPrefix(config.RedirectURI, "http://localhost") {
		store.Options.Secure = false                     // Allow cookies over HTTP on localhost
		store.Options.SameSite = http.SameSiteStrictMode // Use strict mode for localhost to prevent sending cookies with cross-site requests
	}

	if config.TokenParser == nil {
		config.TokenParser = JwtTokenParser{}
	}

	jwksClient := jwks.NewJWKSClient(config)

	return &OAuthClient{
		Config:       config,
		SessionStore: store,
		jwksClient:   jwksClient,
	}
}

// GetOrCreateSession attempts to retrieve the existing session,
// and if it fails, it creates a new session.
func (c *OAuthClient) getSession(r *http.Request) (*sessions.Session, error) {
	session, err := c.SessionStore.Get(r, sessionName)
	if err != nil {
		c.Config.Logger.Error("Gokta could not get session", err)
		// Return an empty value for the session
		session = sessions.NewSession(c.SessionStore, sessionName)
	}
	return session, nil
}

// Middleware returns a new HTTP middleware for handling authentication.
func (c *OAuthClient) Middleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

			c.Config.Logger.Debug("Gokta middleware called for", r.URL.Path)

			session, err := c.getSession(r)
			if err != nil {
				http.Error(w, "Could not get session", http.StatusInternalServerError)
				return
			}

			// Check if the token has expired
			expiresValue, ok := session.Values["auth_expires"].(int64)
			if !ok {
				// Token expiration not found; initiate re-authentication
				c.Config.Logger.Info("Gokta token expiration not found, redirecting to login")
				c.RedirectToLogin(w, r)
				return
			}

			expiration := time.Unix(expiresValue, 0)
			if time.Now().After(expiration) {
				// Token has expired; initiate re-authentication
				c.Config.Logger.Info("Gokta token expired, redirecting to login")
				c.RedirectToLogin(w, r)
				return
			}

			// User is authenticated; serve the next handler
			c.Config.Logger.Debug("Gokta user authenticated, serving next handler")
			next.ServeHTTP(w, r)
		})
	}
}

// RedirectToLogin redirects the user to Okta's login page.
func (c *OAuthClient) RedirectToLogin(w http.ResponseWriter, r *http.Request) {
	// Generate a new state string for this authentication attempt
	state, err := generateState()
	if err != nil {
		c.Config.Logger.Error("Gokta could not generate state", err)
		http.Error(w, "Could not generate state", http.StatusInternalServerError)
		return
	}

	// Store the state string in the session for later validation
	session, err := c.getSession(r)
	if err != nil {
		http.Error(w, "Could not get session", http.StatusInternalServerError)
		return
	}
	session.Values["state"] = state
	err = session.Save(r, w)
	if err != nil {
		c.Config.Logger.Error("Gokta could not save session", err)
		http.Error(w, "Could not save session", http.StatusInternalServerError)
		return
	}
	c.Config.Logger.Debug("Gokta saved state in session: ", state)

	// Construct the OAuth2 URL
	rawURL := c.Config.Issuer + "/v1/authorize"
	authURL, err := url.Parse(rawURL)
	if err != nil {
		c.Config.Logger.Error("Gokta could not parse auth URL: ", rawURL, err)
		http.Error(w, "Could not parse auth URL", http.StatusInternalServerError)
		return
	}

	// If it is set, take the redirect URI from PublicRedirectURI. Otherwise, use RedirectURI.
	redirectURI := c.Config.RedirectURI
	if c.Config.PublicRedirectURI != "" {
		redirectURI = c.Config.PublicRedirectURI
	}

	// Specify the OAuth2 parameters
	params := url.Values{}
	params.Add("client_id", c.Config.ClientID)
	params.Add("response_type", "code")
	params.Add("scope", "openid profile email")
	params.Add("redirect_uri", redirectURI)
	params.Add("state", state)

	authURL.RawQuery = params.Encode()

	// Redirect the user to the constructed URL
	c.Config.Logger.Debug("Gokta redirecting to auth URL: ", authURL.String())
	http.Redirect(w, r, authURL.String(), http.StatusFound)
}

// ExchangeCodeForToken exchanges the authorization code for an access token and ID token
func (c *OAuthClient) ExchangeCodeForToken(authorizationCode string) (*TokenResponse, error) {
	// Construct the token exchange URL
	tokenURL := c.Config.Issuer + "/v1/token"

	// Create the request to exchange the authorization code for tokens
	req, err := http.NewRequest("POST", tokenURL, nil)
	if err != nil {
		return nil, err
	}

	// Add the necessary request headers and parameters
	req.SetBasicAuth(c.Config.ClientID, c.Config.ClientSecret)
	h := req.Header
	h.Add("Accept", "application/json")
	h.Add("Content-Type", "application/x-www-form-urlencoded")
	h.Add("Connection", "close")
	h.Add("Content-Length", "0")

	req.URL.RawQuery = url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {authorizationCode},
		"redirect_uri": {c.Config.RedirectURI},
	}.Encode()

	// Perform the token exchange
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			c.Config.Logger.Error("Gokta could not close response body", err)
		}
	}(resp.Body)

	// Check the response status code
	if resp.StatusCode != http.StatusOK {
		var errResp TokenErrorResponse
		if err := json.NewDecoder(resp.Body).Decode(&errResp); err != nil {
			return nil, err
		}
		if errResp.ErrorCode == "" {
			reader := io.LimitReader(resp.Body, 100)
			body, _ := io.ReadAll(reader)
			return nil, fmt.Errorf("token exchange failed: %d - %s", resp.StatusCode, body)
		}
		return nil, fmt.Errorf("token exchange failed: %s - %s", errResp.ErrorCode, errResp.ErrorSummary)
	}

	// Decode the response body into the TokenResponse struct
	var tokenResponse TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResponse); err != nil {
		return nil, err
	}

	tokenIssueTime := time.Now()
	tokenResponse.ExpirationTime = tokenIssueTime.Add(time.Duration(tokenResponse.ExpiresIn) * time.Second)

	return &tokenResponse, nil
}

// DefaultOktaCallbackHandler handles the redirect from Okta authorization server by default.
func (c *OAuthClient) DefaultOktaCallbackHandler(w http.ResponseWriter, r *http.Request) {
	// Parse the query parameters from the request
	params := r.URL.Query()
	code := params.Get("code")
	state := params.Get("state")

	// Retrieve the original state from your session store
	session, err := c.getSession(r)
	if err != nil {
		http.Error(w, "Could not get session", http.StatusInternalServerError)
		return
	}

	// Verify expected session variables exist
	if session.Values["state"] == nil {
		c.Config.Logger.Error("Gokta state not found in session")
		c.RedirectToLogin(w, r)
		return
	}

	// Verify the state matches
	if session.Values["state"] != state {
		c.Config.Logger.Error("Gokta invalid state parameter")
		http.Error(w, "Invalid state parameter", http.StatusBadRequest)
		return
	}

	// Exchange the code for tokens
	tokenResponse, err := c.ExchangeCodeForToken(code)
	if err != nil {
		c.Config.Logger.Error("Gokta could not exchange token", err)
		http.Error(w, "Could not exchange token", http.StatusInternalServerError)
		return
	}

	// Save the tokens and mark the session as authenticated
	session.Values["access_token"] = tokenResponse.AccessToken
	session.Values["id_token"] = tokenResponse.IDToken
	session.Values["auth_expires"] = tokenResponse.ExpirationTime.Unix()
	if err = session.Save(r, w); err != nil {
		c.Config.Logger.Error("Gokta could not save session", err)
		http.Error(w, "Could not save session", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, c.Config.LoggedInURI, http.StatusFound)
}

// RegisterCallbackRoute uses a RouterFunc to register the callback route.
func (c *OAuthClient) RegisterCallbackRoute(registerFunc RouterFunc) error {
	// Parse the RedirectURI to extract the callback path
	parsedURL, err := url.Parse(c.Config.RedirectURI)
	if err != nil {
		return fmt.Errorf("invalid RedirectURI: %v", err)
	}
	callbackPath := parsedURL.Path

	// Use the provided RouterFunc to register the handler
	registerFunc(callbackPath, http.HandlerFunc(c.DefaultOktaCallbackHandler))

	return nil
}

func (c *OAuthClient) GetUserClaims(w http.ResponseWriter, r *http.Request) (jwt.MapClaims, error) {
	session, err := c.SessionStore.Get(r, sessionName)
	if err != nil {
		return nil, err
	}
	idToken, ok := session.Values["id_token"].(string)
	if !ok {
		return nil, fmt.Errorf("user info not found")
	}
	claims, err := c.jwksClient.ExtractClaims(idToken)
	if err != nil {
		// Check if the error is due to an expired token
		if jwks.IsTokenExpiredError(err) {
			// Token is expired, refresh it
			refreshToken, ok := session.Values["refresh_token"].(string)
			if !ok {
				return nil, fmt.Errorf("refresh token not found")
			}
			tokenResponse, err := c.RefreshTokens(refreshToken)
			if err != nil {
				return nil, err
			}
			// Save the new tokens in the session
			session.Values["id_token"] = tokenResponse.IDToken
			session.Values["access_token"] = tokenResponse.AccessToken
			session.Values["auth_expires"] = tokenResponse.ExpirationTime.Unix()
			err = session.Save(r, w)
			if err != nil {
				return nil, err
			}
			// Retry extracting the claims with the new ID token
			return c.jwksClient.ExtractClaims(tokenResponse.IDToken)
		}
		return nil, err
	}
	return claims, nil
}

// UserClaimsHandler retrieves user information from the session and returns it as JSON.
func (c *OAuthClient) UserClaimsHandler(w http.ResponseWriter, r *http.Request) {

	userInfo, err := c.GetUserClaims(w, r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	err = json.NewEncoder(w).Encode(userInfo)
	if err != nil {
		c.Config.Logger.Error("Gokta could not encode JSON", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

// LogoutURI generates the Okta logout URI.
func (c *OAuthClient) LogoutURI(idToken string) (string, error) {
	// Make sure the PostLogoutRedirectURI is a valid URL
	_, err := url.Parse(c.Config.PostLogoutRedirectURI)
	if err != nil {
		return "", fmt.Errorf("invalid PostLogoutRedirectURI: %v", err)
	}

	// Construct the logout URL
	logoutURL := fmt.Sprintf(
		"%s/v1/logout?id_token_hint=%s&post_logout_redirect_uri=%s",
		strings.TrimSuffix(c.Config.Issuer, "/"),
		url.QueryEscape(idToken),
		url.QueryEscape(c.Config.PostLogoutRedirectURI),
	)

	return logoutURL, nil
}

func (c *OAuthClient) LogoutHandler(w http.ResponseWriter, r *http.Request) {
	// Retrieve the session
	session, err := c.getSession(r)
	if err != nil {
		http.Error(w, "Could not get session", http.StatusInternalServerError)
		return
	}

	// Clear the session
	session.Options.MaxAge = -1 // Set the MaxAge to -1 to delete the session
	err = session.Save(r, w)
	if err != nil {
		c.Config.Logger.Error("Gokta could not save session", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Generate the logout URI and redirect to it
	idToken, ok := session.Values["id_token"].(string)
	if !ok {
		c.Config.Logger.Error("Gokta could not find ID token")
		http.Error(w, "ID token not found", http.StatusInternalServerError)
		return
	}

	logoutURI, err := c.LogoutURI(idToken)
	if err != nil {
		c.Config.Logger.Error("Gokta could not generate logout URI", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, logoutURI, http.StatusFound)
}

func (c *OAuthClient) RefreshTokens(refreshToken string) (*TokenResponse, error) {
	// Construct the token refresh URL
	tokenURL := c.Config.Issuer + "/v1/token"

	// Create the request to refresh the tokens
	req, err := http.NewRequest("POST", tokenURL, nil)
	if err != nil {
		return nil, err
	}

	// Add the necessary request headers and parameters
	req.SetBasicAuth(c.Config.ClientID, c.Config.ClientSecret)
	h := req.Header
	h.Add("Accept", "application/json")
	h.Add("Content-Type", "application/x-www-form-urlencoded")
	h.Add("Connection", "close")
	h.Add("Content-Length", "0")

	req.URL.RawQuery = url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
	}.Encode()

	// Perform the token refresh
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			c.Config.Logger.Error("Gokta could not close response body", err)
		}
	}(resp.Body)

	// Check the response status code
	if resp.StatusCode != http.StatusOK {
		var errResp TokenErrorResponse
		if err := json.NewDecoder(resp.Body).Decode(&errResp); err != nil {
			return nil, err
		}
		if errResp.ErrorCode == "" {
			reader := io.LimitReader(resp.Body, 100)
			body, _ := io.ReadAll(reader)
			return nil, fmt.Errorf("token refresh failed: %d - %s", resp.StatusCode, body)
		}
		return nil, fmt.Errorf("token refresh failed: %s - %s", errResp.ErrorCode, errResp.ErrorSummary)
	}

	// Decode the response body into the TokenResponse struct
	var tokenResponse TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResponse); err != nil {
		return nil, err
	}

	// Update the expiration time of the tokens
	tokenIssueTime := time.Now()
	tokenResponse.ExpirationTime = tokenIssueTime.Add(time.Duration(tokenResponse.ExpiresIn) * time.Second)

	return &tokenResponse, nil
}
