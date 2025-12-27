package otk

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	// RegisterTokenExpiry is the validity period for registration tokens
	RegisterTokenExpiry = 5 * time.Minute
	// RSAKeySize is the size of the RSA key in bits
	RSAKeySize = 2048
)

var (
	ErrTokenExpired = errors.New("registration token has expired")
	ErrTokenInvalid = errors.New("invalid registration token")
)

// RegisterClaims contains the JWT claims for registration tokens
type RegisterClaims struct {
	Sub          string `json:"sub"`
	AppID        string `json:"app_id"`
	SSOServerURL string `json:"sso_server_url"`
	jwt.RegisteredClaims
}

// RegisterTokenManager manages RS256 JWT tokens for user registration
type RegisterTokenManager struct {
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
	keyID      string
	mu         sync.RWMutex
}

// JWKS represents a JSON Web Key Set
type JWKS struct {
	Keys []JWK `json:"keys"`
}

// JWK represents a JSON Web Key
type JWK struct {
	Kty string `json:"kty"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
}

// NewRegisterTokenManager creates a new token manager with auto-generated RSA key pair
func NewRegisterTokenManager() (*RegisterTokenManager, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, RSAKeySize)
	if err != nil {
		return nil, err
	}

	// Generate a random key ID
	kidBytes := make([]byte, 8)
	if _, err := rand.Read(kidBytes); err != nil {
		return nil, err
	}
	keyID := base64.RawURLEncoding.EncodeToString(kidBytes)

	return &RegisterTokenManager{
		privateKey: privateKey,
		publicKey:  &privateKey.PublicKey,
		keyID:      keyID,
	}, nil
}

// GenerateToken creates a JWT token for user registration using RS256
func (m *RegisterTokenManager) GenerateToken(sub, appID, ssoServerURL string) (string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	now := time.Now()
	claims := RegisterClaims{
		Sub:          sub,
		AppID:        appID,
		SSOServerURL: ssoServerURL,
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(RegisterTokenExpiry)),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = m.keyID

	return token.SignedString(m.privateKey)
}

// ValidateToken validates a registration JWT token and returns the claims
func (m *RegisterTokenManager) ValidateToken(tokenString string) (sub, appID, ssoServerURL string, err error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	token, err := jwt.ParseWithClaims(tokenString, &RegisterClaims{}, func(token *jwt.Token) (interface{}, error) {
		// Explicitly check the signing method to prevent algorithm attacks
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, ErrTokenInvalid
		}
		// Verify key ID matches
		if kid, ok := token.Header["kid"].(string); !ok || kid != m.keyID {
			return nil, ErrTokenInvalid
		}
		return m.publicKey, nil
	})

	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return "", "", "", ErrTokenExpired
		}
		return "", "", "", ErrTokenInvalid
	}

	claims, ok := token.Claims.(*RegisterClaims)
	if !ok || !token.Valid {
		return "", "", "", ErrTokenInvalid
	}

	return claims.Sub, claims.AppID, claims.SSOServerURL, nil
}

// GetJWKS returns the public key in JWKS format for client verification
func (m *RegisterTokenManager) GetJWKS() JWKS {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return JWKS{
		Keys: []JWK{
			{
				Kty: "RSA",
				Use: "sig",
				Alg: "RS256",
				Kid: m.keyID,
				N:   base64.RawURLEncoding.EncodeToString(m.publicKey.N.Bytes()),
				E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(m.publicKey.E)).Bytes()),
			},
		},
	}
}

// GetJWKSJSON returns the JWKS as JSON bytes
func (m *RegisterTokenManager) GetJWKSJSON() ([]byte, error) {
	return json.Marshal(m.GetJWKS())
}
