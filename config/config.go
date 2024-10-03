package config

import (
	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/sessions"
	"github.com/zymsys/gokta/logging"
	"net/http"
)

type TokenParser interface {
	Parse(tokenString string, keyFunc jwt.Keyfunc, options ...jwt.ParserOption) (*jwt.Token, error)
}

type HTTPClient interface {
	Get(url string) (*http.Response, error)
}

// Config for the Okta OAuth client.
type Config struct {
	ClientID              string
	ClientSecret          string
	Issuer                string
	RedirectURI           string
	SessionKey            string     // Key for secure cookie encryption
	LoggedInURI           string     // The URI to redirect to after successful login
	PostLogoutRedirectURI string     // URI to redirect to after logging out from Okta
	Scope                 string     // OAuth scope
	HttpClient            HTTPClient // Optional HTTP client to use for requests
	Logger                logging.Logger
	TokenParser           TokenParser
	SessionStore          sessions.Store
}
