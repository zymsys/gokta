package jwks

import (
	"bytes"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"github.com/zymsys/gokta/config"
	"github.com/zymsys/gokta/logging"
	"io"
	"net/http"
	"strings"
	"testing"
)

type MockHTTPClient struct {
	Response *http.Response
	Err      error
}

func (m *MockHTTPClient) Get(string) (*http.Response, error) {
	return m.Response, m.Err
}

type MockTokenParser struct {
	Token *jwt.Token
	Err   error
}

func (m MockTokenParser) Parse(_ string, keyFunc jwt.Keyfunc, _ ...jwt.ParserOption) (*jwt.Token, error) {
	if m.Err != nil {
		return nil, m.Err
	}
	if m.Token != nil {
		// Simulate invoking the keyFunc with the provided mock token
		_, err := keyFunc(m.Token)
		if err != nil {
			return nil, err
		}
		return m.Token, nil
	}
	return jwt.New(jwt.SigningMethodRS256), nil
}

func buildMockJWKSString() string {
	nB64 := "2A6XcsBfSnkwepGiiqljp18fEhkmcrIrB1vDUpzkkpjCJz96cFjPbcXHw7Y9RE9BHvdmcagZRzmeih4vEUkfIeIt6OtQZgYg06y9btNXyU-NxCndCBuTSRpyVcWIJ7aYDISnFMnHVxfw5o7oo3_OinE6O2u2R9950WAMkmObCMJENCquh0a4FZchltZj0KESkHpjq-t4iJS--HeHEMRaenSguKVoKcGspeZy5YxXgmcBt-fVSx14YPB1LPY4rUrIHzX8V5nZiT6YAeJMPCDSv82ZFWp6UzrLS6VoUL5hBonhgY8M687NicHwySWnqJGQocz5iqoihChC70v7v5e1Rw"
	eB64 := "AQAB"
	return `{"keys": [{"kty": "RSA", "kid": "key1", "n": "` + nB64 + `", "e": "` + eB64 + `"}]}`
}

func buildMockJWKSData() []byte {
	return []byte(buildMockJWKSString())
}

func buildMockJSONWebKeys() JSONWebKeys {
	jwksJSON := buildMockJWKSString()

	var jwks JWKS
	err := json.Unmarshal([]byte(jwksJSON), &jwks)
	if err != nil {
		panic("Failed to unmarshal JWKS JSON: " + err.Error())
	}

	if len(jwks.Keys) == 0 {
		panic("No keys found in JWKS")
	}

	return jwks.Keys[0]
}

type ErrorReadCloser struct{}

func (erc *ErrorReadCloser) Read([]byte) (n int, err error) {
	return 0, fmt.Errorf("mock read error")
}

func (erc *ErrorReadCloser) Close() error {
	return nil
}

func TestNewJWKSClient(t *testing.T) {
	// Mock configuration
	mockConfig := config.Config{
		Issuer:     "https://example.com",
		ClientID:   "client-id",
		Logger:     logging.NoOpLogger{},
		HttpClient: &http.Client{}, // Use a default http client or a mock if necessary
	}

	// Create JWKSClient
	client := NewJWKSClient(mockConfig)

	// Assertions
	if client.issuer != mockConfig.Issuer {
		t.Errorf("Expected issuer to be %s, got %s", mockConfig.Issuer, client.issuer)
	}
	if client.clientId != mockConfig.ClientID {
		t.Errorf("Expected client ID to be %s, got %s", mockConfig.ClientID, client.clientId)
	}
	if client.logger != mockConfig.Logger {
		t.Error("Logger is not set correctly")
	}
	if client.httpClient != mockConfig.HttpClient {
		t.Error("HTTP client is not set correctly")
	}
	if client.rsaKeysCache == nil {
		t.Error("RSA keys cache map is not initialized")
	}
}

func TestFetchHTTPResponse_Success(t *testing.T) {
	// Mock HTTP client
	mockResponse := &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(bytes.NewBufferString("mock response body")),
	}
	mockClient := &MockHTTPClient{
		Response: mockResponse,
	}

	// Create JWKSClient with the mock client
	client := &JWKSClient{
		httpClient: mockClient,
		issuer:     "https://example.com",
	}

	// Call fetchHTTPResponse
	body, err := client.fetchHTTPResponse("https://example.com/v1/keys")

	// Assertions
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
	expectedBody := "mock response body"
	if string(body) != expectedBody {
		t.Errorf("Expected body to be %s, got %s", expectedBody, body)
	}
}

func TestFetchHTTPResponse_RequestError(t *testing.T) {
	// Mock HTTP client to return an error
	mockClient := &MockHTTPClient{
		Err: fmt.Errorf("mock request error"),
	}

	// Create JWKSClient with the mock client
	client := &JWKSClient{
		httpClient: mockClient,
		logger:     logging.NoOpLogger{},
		issuer:     "https://example.com",
	}

	// Call fetchHTTPResponse
	_, err := client.fetchHTTPResponse("https://example.com/v1/keys")

	// Assertions
	if err == nil {
		t.Error("Expected an error, got nil")
	}
	if !strings.Contains(err.Error(), "mock request error") {
		t.Errorf("Expected the error message to contain 'mock request error', got %v", err)
	}
}

func TestFetchHTTPResponse_Non200Response(t *testing.T) {
	// Mock HTTP response with non-200 status code
	mockResponse := &http.Response{
		StatusCode: http.StatusNotFound, // 404
		Body:       io.NopCloser(bytes.NewBufferString("")),
	}
	mockClient := &MockHTTPClient{
		Response: mockResponse,
	}

	// Create JWKSClient with the mock client
	client := &JWKSClient{
		httpClient: mockClient,
		logger:     logging.NoOpLogger{},
		issuer:     "https://example.com",
	}

	// Call fetchHTTPResponse
	_, err := client.fetchHTTPResponse("https://example.com/v1/keys")

	// Assertions
	if err == nil {
		t.Error("Expected an error, got nil")
	}
}

func TestFetchHTTPResponse_BodyReadError(t *testing.T) {
	// Mock HTTP response where reading the body returns an error
	mockResponse := &http.Response{
		StatusCode: http.StatusOK,
		Body:       &ErrorReadCloser{},
	}
	mockClient := &MockHTTPClient{
		Response: mockResponse,
	}

	// Create JWKSClient with the mock client
	client := &JWKSClient{
		httpClient: mockClient,
		logger:     logging.NoOpLogger{},
		issuer:     "https://example.com",
	}

	// Call fetchHTTPResponse
	_, err := client.fetchHTTPResponse("https://example.com/v1/keys")

	// Assertions
	if err == nil {
		t.Error("Expected an error, got nil")
	}
}

func TestUpdateJWKSCache_Success(t *testing.T) {
	// Create JWKSClient with a mock logger
	client := &JWKSClient{
		logger: logging.NoOpLogger{},
	}

	// Mock JWKS JSON data
	mockJWKSData := buildMockJWKSData()

	// Call updateJWKSCache
	err := client.updateJWKSCache(mockJWKSData)

	// Assertions
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
	if len(client.rsaKeysCache) == 0 {
		t.Error("RSA keys cache is not updated")
	}
}

func TestUpdateJWKSCache_JSONDecodingError(t *testing.T) {
	// Create JWKSClient with a mock logger
	client := &JWKSClient{
		logger: logging.NoOpLogger{},
	}

	// Mock invalid JWKS JSON data
	invalidJWKSData := []byte("{invalid-json}")

	// Call updateJWKSCache
	err := client.updateJWKSCache(invalidJWKSData)

	// Assertions
	if err == nil {
		t.Error("Expected a JSON decoding error, got nil")
	}
}

func TestUpdateJWKSCache_ConversionError(t *testing.T) {
	// Create JWKSClient with a mock logger
	client := &JWKSClient{
		logger: logging.NoOpLogger{},
	}

	// Mock JWKS JSON data with a non-RSA key type
	nonRSAJWKSData := []byte(`{"keys": [{"kty": "EC", "kid": "key1"}]}`)

	// Call updateJWKSCache
	err := client.updateJWKSCache(nonRSAJWKSData)

	// Assertions
	if err == nil {
		t.Error("Expected an error due to non-RSA key type, got nil")
	}
	if !strings.Contains(err.Error(), "JWK is not of type RSA") {
		t.Errorf("Expected error to contain 'JWK is not of type RSA', got %v", err)
	}
}

func TestConvertJWKToRSAPublicKey_Success(t *testing.T) {
	// Setup
	jwk := buildMockJSONWebKeys()
	client := JWKSClient{} // Initialize a JWKSClient with default values

	// Execute
	rsaKey, err := client.convertJWKToRSAPublicKey(jwk)

	// Verify
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
	if rsaKey == nil {
		t.Error("Expected a valid RSA key, got nil")
	}
}

func TestConvertJWKToRSAPublicKey_NonRSAKey(t *testing.T) {
	// Setup
	jwk := JSONWebKeys{
		Kty: "non-RSA-type",
	}
	client := JWKSClient{
		logger: logging.NoOpLogger{},
	}

	// Execute
	_, err := client.convertJWKToRSAPublicKey(jwk)

	// Verify
	expectedError := "JWK is not of type RSA"
	if !strings.Contains(err.Error(), expectedError) {
		t.Errorf("Expected error to contain '%s', got %v", expectedError, err)
	}
}

func TestConvertJWKToRSAPublicKey_DecodingError(t *testing.T) {
	// Setup
	jwk := JSONWebKeys{
		Kty: "RSA",
		N:   "!!!invalid_base64", // Clearly malformed base64 string for modulus
		E:   "!!!invalid_base64", // Clearly malformed base64 string for exponent
	}
	client := JWKSClient{
		logger: logging.NoOpLogger{},
	}

	// Execute
	_, err := client.convertJWKToRSAPublicKey(jwk)

	// Verify
	if err == nil {
		t.Error("Expected an error, got none")
	}
	expectedError := "Failed to decode"
	if !strings.Contains(err.Error(), expectedError) {
		t.Errorf("Expected error to contain '%s', got %v", expectedError, err)
	}
}

func TestConvertJWKToRSAPublicKey_LargeExponent(t *testing.T) {
	// Setup
	largeExponent := []byte{1, 0, 0, 0, 0} // 5 bytes, definitely too large for a 32-bit int

	jwk := JSONWebKeys{
		Kty: "RSA",
		N:   base64.RawURLEncoding.EncodeToString([]byte{1, 2, 3}), // Some valid base64 string for modulus
		E:   base64.RawURLEncoding.EncodeToString(largeExponent),
	}
	client := JWKSClient{
		logger: logging.NoOpLogger{},
	}

	// Execute
	_, err := client.convertJWKToRSAPublicKey(jwk)

	// Verify
	expectedError := "Exponent too large for RSA key" // Adjust according to actual error message
	if err == nil || err.Error() != expectedError {
		t.Errorf("Expected error '%s', got '%v'", expectedError, err)
	}
}

func TestExtractClaimsCached_Success(t *testing.T) {
	// Build mock JWKS
	mockJWKS := buildMockJSONWebKeys()

	// Convert mock JWKS to RSA public key
	client := JWKSClient{
		logger:       logging.NoOpLogger{},
		rsaKeysCache: make(map[string]*rsa.PublicKey),
	}
	rsaKey, err := client.convertJWKToRSAPublicKey(mockJWKS)
	if err != nil {
		t.Fatalf("Failed to convert mock JWKS to RSA public key: %v", err)
	}

	// Populate rsaKeysCache with the mock RSA public key
	client.rsaKeysCache[mockJWKS.Kid] = rsaKey

	// Mock token with correct signing method and header
	mockToken := &jwt.Token{
		Valid: true,
		Claims: jwt.MapClaims{
			"claim1": "value1",
			"claim2": "value2",
		},
		Method: jwt.SigningMethodRS256,
		Header: map[string]interface{}{
			"kid": mockJWKS.Kid,
		},
	}

	// Mock token parser
	mockParser := MockTokenParser{
		Token: mockToken,
		Err:   nil,
	}

	// Update client with mocked token parser
	client.tokenParser = mockParser

	// Mock a valid ID token
	idToken := "mocked.valid.token"

	// Execute
	claims, err := client.extractClaimsCached(idToken)

	// Assert
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	// Check if claims are as expected
	if val, ok := claims["claim1"]; !ok || val != "value1" {
		t.Errorf("Expected claim1 to be 'value1', got '%v'", val)
	}
	if val, ok := claims["claim2"]; !ok || val != "value2" {
		t.Errorf("Expected claim2 to be 'value2', got '%v'", val)
	}
}

func TestExtractClaimsCached_InvalidSignature(t *testing.T) {
	// Mock token parser to return an invalid token error
	mockParser := MockTokenParser{
		Token: nil,
		Err:   fmt.Errorf("invalid token signature"),
	}

	// Create JWKSClient with mocked token parser
	client := JWKSClient{
		logger:       logging.NoOpLogger{},
		rsaKeysCache: make(map[string]*rsa.PublicKey),
		tokenParser:  mockParser,
	}

	// Mock an invalid ID token
	idToken := "mocked.invalid.token"

	// Execute
	_, err := client.extractClaimsCached(idToken)

	// Assert
	if err == nil {
		t.Error("Expected an error, got nil")
	} else if !strings.Contains(err.Error(), "invalid token signature") {
		t.Errorf("Expected error to contain 'invalid token signature', got %v", err)
	}
}

func TestExtractClaimsCached_MissingKid(t *testing.T) {
	// Mock token parser to return a token without 'kid' in header
	mockToken := &jwt.Token{
		Valid: true,
		Header: map[string]interface{}{
			"alg": "RS256", // Keep this to simulate the header
		},
		Claims: jwt.MapClaims{},
		Method: jwt.SigningMethodRS256, // Correctly set the signing method
	}
	mockParser := MockTokenParser{
		Token: mockToken,
		Err:   nil,
	}

	// Create JWKSClient with mocked token parser
	client := JWKSClient{
		logger:       logging.NoOpLogger{},
		rsaKeysCache: make(map[string]*rsa.PublicKey),
		tokenParser:  mockParser,
	}

	// Mock a token with missing 'kid'
	idToken := "mocked.token.without.kid"

	// Execute
	_, err := client.extractClaimsCached(idToken)

	// Assert
	if err == nil {
		t.Error("Expected an error, got nil")
	} else if !strings.Contains(err.Error(), "token header 'kid' is missing or not a string") {
		t.Errorf("Expected error to contain 'token header 'kid' is missing or not a string', got %v", err)
	}
}

func TestExtractClaimsCached_NonRSASigningMethod(t *testing.T) {
	// Create a JWKSClient instance with necessary mocks
	client := JWKSClient{
		logger:       logging.NoOpLogger{},
		rsaKeysCache: make(map[string]*rsa.PublicKey),
		tokenParser:  MockTokenParser{}, // Assuming MockTokenParser can handle non-RSA tokens
	}

	// Mock token with a non-RSA signing method (e.g., HMAC)
	mockToken := &jwt.Token{
		Valid: true,
		Claims: jwt.MapClaims{
			"claim1": "value1",
			"claim2": "value2",
		},
		Method: jwt.SigningMethodHS256, // Non-RSA signing method
		Header: map[string]interface{}{
			"alg": "HS256",
		},
	}

	// Mock token parser to return the mock token
	mockParser := MockTokenParser{
		Token: mockToken,
		Err:   nil,
	}

	// Update client with mocked token parser
	client.tokenParser = mockParser

	// Mock a valid ID token
	idToken := "mocked.valid.token"

	// Execute
	_, err := client.extractClaimsCached(idToken)

	// Assert
	if err == nil {
		t.Errorf("Expected an error for non-RSA signing method, got no error")
	} else if !strings.Contains(err.Error(), "unexpected signing method") {
		t.Errorf("Expected 'unexpected signing method' error, got %v", err)
	}
}

func TestExtractClaims_SuccessWithValidTokenAndJWKS(t *testing.T) {
	// Setup JWKSClient with necessary mocks and a pre-populated JWKS cache
	mockJWKS := buildMockJSONWebKeys()
	client := JWKSClient{
		logger: logging.NoOpLogger{},
		rsaKeysCache: map[string]*rsa.PublicKey{
			mockJWKS.Kid: {}, // Mock RSA public key
		},
		jwks: &JWKS{Keys: []JSONWebKeys{mockJWKS}},
		tokenParser: MockTokenParser{
			Token: &jwt.Token{
				Valid: true,
				Claims: jwt.MapClaims{
					"claim1": "value1",
					"claim2": "value2",
				},
				Method: jwt.SigningMethodRS256,
				Header: map[string]interface{}{
					"kid": mockJWKS.Kid,
				},
			},
			Err: nil,
		},
	}

	// Mock a valid ID token
	idToken := "mocked.valid.token"

	// Execute
	claims, err := client.ExtractClaims(idToken)

	// Assert
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if val, ok := claims["claim1"]; !ok || val != "value1" {
		t.Errorf("Expected claim1 to be 'value1', got '%v'", val)
	}
	if val, ok := claims["claim2"]; !ok || val != "value2" {
		t.Errorf("Expected claim2 to be 'value2', got '%v'", val)
	}
}

func TestExtractClaims_FetchJWKSWhenCacheIsEmpty(t *testing.T) {
	// Setup JWKSClient with necessary mocks and empty JWKS cache
	client := JWKSClient{
		logger:       logging.NoOpLogger{},
		rsaKeysCache: make(map[string]*rsa.PublicKey),
		httpClient: &MockHTTPClient{
			Response: &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader(buildMockJWKSString())),
			},
			Err: nil,
		},
	}

	// Mock token with valid signature and claims
	mockJWKS := buildMockJSONWebKeys()
	rsaKey, _ := client.convertJWKToRSAPublicKey(mockJWKS)
	client.rsaKeysCache[mockJWKS.Kid] = rsaKey

	mockToken := &jwt.Token{
		Valid: true,
		Claims: jwt.MapClaims{
			"claim1": "value1",
			"claim2": "value2",
		},
		Method: jwt.SigningMethodRS256,
		Header: map[string]interface{}{
			"kid": mockJWKS.Kid,
		},
	}

	// Mock token parser to return the mock token
	mockParser := MockTokenParser{
		Token: mockToken,
		Err:   nil,
	}
	client.tokenParser = mockParser

	// Mock a valid ID token
	idToken := "mocked.valid.token"

	// Execute
	claims, err := client.ExtractClaims(idToken)

	// Assert
	if err != nil {
		t.Fatalf("Expected no error when fetching JWKS, got %v", err)
	}
	if val, ok := claims["claim1"]; !ok || val != "value1" {
		t.Errorf("Expected claim1 to be 'value1', got '%v'", val)
	}
	if val, ok := claims["claim2"]; !ok || val != "value2" {
		t.Errorf("Expected claim2 to be 'value2', got '%v'", val)
	}
}

func TestExtractClaims_RefreshJWKSOnSignatureValidationFailure(t *testing.T) {
	// Setup JWKSClient with necessary mocks
	client := JWKSClient{
		logger:       logging.NoOpLogger{},
		rsaKeysCache: make(map[string]*rsa.PublicKey), // Initially empty cache
		tokenParser: MockTokenParser{
			Token: &jwt.Token{
				Valid: false, // Simulate validation failure
			},
			Err: jwt.ErrTokenSignatureInvalid, // Force signature validation error
		},
	}
	client.httpClient = &MockHTTPClient{
		Response: &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(buildMockJWKSString())),
		},
		Err: nil,
	}

	// Mock a valid ID token
	idToken := "mocked.invalid.token"

	// Execute
	_, err := client.ExtractClaims(idToken)

	// Assert
	if err == nil {
		t.Errorf("Expected an error due to signature validation failure, got no error")
	}
	if len(client.rsaKeysCache) == 0 {
		t.Errorf("Expected JWKS cache to be refreshed and populated, found empty")
	}
}

func TestExtractClaims_HandleErrorsInJWKSFetchOrTokenValidation(t *testing.T) {
	// Setup JWKSClient with necessary mocks
	client := JWKSClient{
		logger:       logging.NoOpLogger{},
		rsaKeysCache: make(map[string]*rsa.PublicKey),
		tokenParser: MockTokenParser{
			Token: nil,
			Err:   fmt.Errorf("token validation error"),
		},
	}
	client.httpClient = &MockHTTPClient{
		Response: nil, // Simulate JWKS fetch error
		Err:      fmt.Errorf("failed to fetch JWKS"),
	}

	// Mock a valid ID token
	idToken := "mocked.valid.token"

	// Execute
	_, err := client.ExtractClaims(idToken)

	// Assert
	if err == nil {
		t.Errorf("Expected an error due to JWKS fetching or token validation, got no error")
	}
}
