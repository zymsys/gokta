package jwks

import (
	"bytes"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"github.com/zymsys/gokta/config"
	"github.com/zymsys/gokta/logging"
	"io"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"
)

// JWKS represents JSON Web Key Set
type JWKS struct {
	Keys []JSONWebKeys `json:"keys"`
}

// JSONWebKeys represents a public key in JWKS
type JSONWebKeys struct {
	Kty string   `json:"kty"`
	Kid string   `json:"kid"`
	Use string   `json:"use"`
	N   string   `json:"n"`
	E   string   `json:"e"`
	X5c []string `json:"x5c"`
}

type JWKSClient struct {
	jwks         *JWKS
	rsaKeysCache map[string]*rsa.PublicKey
	lastUpdated  time.Time
	mutex        sync.RWMutex
	logger       logging.Logger
	issuer       string
	clientId     string
	config       config.Config
}

func NewJWKSClient(config config.Config) *JWKSClient {
	return &JWKSClient{
		rsaKeysCache: make(map[string]*rsa.PublicKey),
		config:       config,
		logger:       config.Logger,
	}
}

// fetchJWKS retrieves the JWKS (JSON Web Key Set) from Okta's JWKS endpoint.
// It locks the JWKSClient's mutex to ensure thread-safe updates to the JWKS and RSA keys cache.
// After fetching, it parses the JWKS and updates the RSA keys cache with new keys.
// This function is typically called when initializing the JWKSClient or when the JWKS needs to be refreshed.
func (c *JWKSClient) fetchJWKS() error {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	c.logger.Debug("Fetching JWKS from Okta")

	body, err := c.fetchHTTPResponse(fmt.Sprintf("%s/v1/keys", strings.TrimSuffix(c.config.Issuer, "/")))
	if err != nil {
		return err
	}

	return c.updateJWKSCache(body)
}

// fetchHTTPResponse handles the HTTP request and response.
func (c *JWKSClient) fetchHTTPResponse(url string) ([]byte, error) {
	resp, err := c.config.HttpClient.Get(url)
	if err != nil {
		return nil, logging.LogAndReturnError(c.logger.Error, "Failed to fetch JWKS from URL: ", c.config.Issuer, " - error: ", err)
	}
	defer func(Body io.ReadCloser) {
		deferredErr := Body.Close()
		if deferredErr != nil {
			c.logger.Error("Failed to close response body:", deferredErr)
		}
	}(resp.Body)

	// Check for non-success status code
	if resp.StatusCode != http.StatusOK {
		return nil, logging.LogAndReturnError(c.logger.Error, "Received non-200 status code from JWKS endpoint: ", resp.StatusCode, " - URL: ", c.config.Issuer)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, logging.LogAndReturnError(c.logger.Error, "Failed to read response body:", err)
	}

	return body, nil
}

// updateJWKSCache decodes the JWKS JSON and updates the RSA keys cache.
func (c *JWKSClient) updateJWKSCache(body []byte) error {
	var jwks JWKS
	err := json.NewDecoder(bytes.NewReader(body)).Decode(&jwks)
	if err != nil {
		return logging.LogAndReturnError(c.logger.Error, "Failed to decode JWKS JSON response from: ", c.config.Issuer, " - error: ", err)
	}

	// Update the RSA keys cache
	c.rsaKeysCache = make(map[string]*rsa.PublicKey)
	for _, key := range jwks.Keys {
		rsaKey, err := c.convertJWKToRSAPublicKey(key)
		if err != nil {
			return err
		}
		c.rsaKeysCache[key.Kid] = rsaKey
	}

	c.jwks = &jwks
	c.logger.Info("Successfully fetched JWKS")
	return nil
}

// IsTokenExpiredError checks if the provided error is a JWT signature validation error or a token expiration error.
// This is used to determine if a token's signature validation failure is due to an outdated JWKS,
// or if the token is expired, in which case the JWKS can be refreshed and validation retried.
func IsTokenExpiredError(err error) bool {
	return errors.Is(err, jwt.ErrTokenExpired)
}

// convertJWKToRSAPublicKey converts a JSON Web Key (JWK) to an RSA public key.
// It first checks if the key type (Kty) is RSA; if not, it logs and returns an error.
// The function decodes the base64 URL encoded modulus (N) and exponent (E) of the JWK,
// and then constructs an RSA public key using these values.
// This function is crucial for validating JWT signatures against the public key.
func (c *JWKSClient) convertJWKToRSAPublicKey(jwk JSONWebKeys) (*rsa.PublicKey, error) {
	// Check for RSA key type
	if jwk.Kty != "RSA" {
		return nil, logging.LogAndReturnError(c.logger.Error, "JWK is not of type RSA, kid:", jwk.Kid,
			" Kty:", jwk.Kty)
	}

	// Decode the base64 URL encoded modulus (n)
	decodedN, err := base64.RawURLEncoding.DecodeString(jwk.N)
	if err != nil {
		return nil, logging.LogAndReturnError(c.logger.Error, "Failed to decode JWK modulus:", err)
	}
	n := new(big.Int).SetBytes(decodedN)

	// Decode the base64 URL encoded exponent (e)
	decodedE, err := base64.RawURLEncoding.DecodeString(jwk.E)
	if err != nil {
		return nil, logging.LogAndReturnError(c.logger.Error, "Failed to decode JWK exponent:", err)
	}

	var e int
	if len(decodedE) <= 4 {
		// Convert to int (big-endian encoding as per RFC-7518)
		for _, b := range decodedE {
			e = (e << 8) | int(b)
		}
	} else {
		// Handle large exponent with big.Int
		bigE := new(big.Int).SetBytes(decodedE)
		if bigE.IsInt64() && bigE.Int64() <= int64(^uint32(0)) {
			e = int(bigE.Int64())
		} else {
			// Exponent is too large for an int
			return nil, logging.LogAndReturnError(c.logger.Error, "Exponent too large for RSA key")
		}
	}

	// Construct RSA public key
	publicKey := &rsa.PublicKey{
		N: n,
		E: e,
	}

	return publicKey, nil
}

// extractClaimsCached decodes the ID token, validates it, and extracts the claims (user information).
// It uses the cached RSA keys for validation. The function parses the token, verifies its signature,
// and checks its validity. If the token is invalid or the claims cannot be extracted, it returns an error.
// This method is optimized to use the RSA keys cache to avoid fetching JWKS for every token validation.
func (c *JWKSClient) extractClaimsCached(idToken string) (jwt.MapClaims, error) {
	c.logger.Debug("Parsing and validating ID token")
	token, err := c.config.TokenParser.Parse(idToken, func(token *jwt.Token) (interface{}, error) {
		// Verify the token algorithm
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		kid, ok := token.Header["kid"].(string)
		if !ok {
			return nil, fmt.Errorf("token header 'kid' is missing or not a string")
		}

		if rsaKey, found := c.rsaKeysCache[kid]; found {
			return rsaKey, nil
		}
		return nil, logging.LogAndReturnError(c.logger.Error, "RSA key not found in cache for kid: ", kid)
	})

	if err != nil {
		return nil, logging.LogAndReturnError(c.logger.Error, "Error parsing ID token: ", idToken, " - error: ", err)
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		invalidReason := "unknown"
		if !ok {
			invalidReason = "claims type assertion failed"
		} else if !token.Valid {
			invalidReason = "token is invalid"
		}
		return nil, logging.LogAndReturnError(c.logger.Warn, "Invalid token: ", idToken, " - reason: ", invalidReason)
	}

	return claims, nil
}

// ExtractClaims decodes the ID token, validates it, and extracts the user information.
// If the JWKS cache is empty, it fetches the JWKS before proceeding.
// In case of a signature validation error, it attempts to refresh the JWKS and retries validation.
// This approach ensures that the validation process is robust against changes in the JWKS,
// such as key rotation or addition of new keys.
func (c *JWKSClient) ExtractClaims(idToken string) (jwt.MapClaims, error) {
	if c.jwks == nil {
		c.logger.Info("JWKS cache is empty, fetching JWKS")
		if err := c.fetchJWKS(); err != nil {
			return nil, err
		}
	}
	claims, err := c.extractClaimsCached(idToken)
	if err != nil {
		if IsTokenExpiredError(err) {
			// Signature validation failed, possibly due to an outdated JWKS. Refresh JWKS and retry.
			c.logger.Warn("Signature validation failed, refreshing JWKS:", err)
			if refreshErr := c.fetchJWKS(); refreshErr != nil {
				return nil, refreshErr // JWKS refresh failed
			}
			// Retry validation with the refreshed JWKS
			return c.extractClaimsCached(idToken)
		}
		c.logger.Error("Failed to refresh JWKS:", err)
		return nil, err // Other errors
	}
	c.logger.Debug("Token successfully validated")
	return claims, nil // Token is valid
}
