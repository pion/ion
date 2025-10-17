// SPDX-FileCopyrightText: 2025 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package metrics

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
)

const (
	testPlainToken = "testtoken123"
	testPassword   = "testpass"
	testUsername   = "testuser"
)

func generatePasswordHash(plainPassword string) (string, error) {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(plainPassword), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}

	return hex.EncodeToString(hashedPassword), nil
}

func generateTokenHash(plainToken string) string {
	hash := sha256.Sum256([]byte(plainToken))

	return hex.EncodeToString(hash[:])
}

func TestHashingMethodString(t *testing.T) {
	assert.NotEmpty(t, HashingBcrypt.String())
	assert.NotEmpty(t, HashingSHA256.String())
	assert.NotEmpty(t, HashingNone.String())
}

func TestBasicAuth(t *testing.T) {
	service := NewPromService(Options{Namespace: "test"})
	plainPassword := testPassword
	username := testUsername

	bcryptHash, err := bcrypt.GenerateFromPassword([]byte(plainPassword), bcrypt.DefaultCost)
	require.NoError(t, err)
	bcryptHashHex := hex.EncodeToString(bcryptHash)

	sha256Hash := sha256.Sum256([]byte(plainPassword))
	sha256HashHex := hex.EncodeToString(sha256Hash[:])

	testCases := []struct {
		name            string
		password        string
		requestUser     string
		requestPass     string
		expectedWWWAuth string
		method          hashingMethod
		expectedStatus  int
	}{
		{
			"plain - valid", plainPassword, username, plainPassword, "",
			HashingNone, http.StatusOK,
		},
		{
			"plain - invalid pass", plainPassword, username, "wrongpass",
			`Basic realm="metrics"`, HashingNone, http.StatusUnauthorized,
		},
		{
			"plain - invalid user", plainPassword, "wronguser", plainPassword,
			`Basic realm="metrics"`, HashingNone, http.StatusUnauthorized,
		},
		{
			"plain - no auth", plainPassword, "", "",
			`Basic realm="metrics"`, HashingNone, http.StatusUnauthorized,
		},
		{
			"plain - empty pass", plainPassword, username, "",
			`Basic realm="metrics"`, HashingNone, http.StatusUnauthorized,
		},
		{
			"bcrypt - valid", bcryptHashHex, username, plainPassword, "",
			HashingBcrypt, http.StatusOK,
		},
		{
			"bcrypt - invalid pass", bcryptHashHex, username, "wrongpass",
			`Basic realm="metrics"`, HashingBcrypt, http.StatusUnauthorized,
		},
		{
			"bcrypt - invalid user", bcryptHashHex, "wronguser", plainPassword,
			`Basic realm="metrics"`, HashingBcrypt, http.StatusUnauthorized,
		},
		{
			"bcrypt - no auth", bcryptHashHex, "", "",
			`Basic realm="metrics"`, HashingBcrypt, http.StatusUnauthorized,
		},
		{
			"bcrypt - invalid hex", "invalid-hex", username, plainPassword,
			`Basic realm="metrics"`, HashingBcrypt, http.StatusUnauthorized,
		},
		{
			"sha256 - valid", sha256HashHex, username, plainPassword, "",
			HashingSHA256, http.StatusOK,
		},
		{
			"sha256 - invalid pass", sha256HashHex, username, "wrongpass",
			`Basic realm="metrics"`, HashingSHA256, http.StatusUnauthorized,
		},
		{
			"sha256 - invalid user", sha256HashHex, "wronguser", plainPassword,
			`Basic realm="metrics"`, HashingSHA256, http.StatusUnauthorized,
		},
		{
			"sha256 - no auth", sha256HashHex, "", "",
			`Basic realm="metrics"`, HashingSHA256, http.StatusUnauthorized,
		},
		{
			"sha256 - invalid hex", "invalid-hex-not-64-chars", username, plainPassword,
			`Basic realm="metrics"`, HashingSHA256, http.StatusUnauthorized,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			handler := service.Handler(WithBasicAuth(username, tc.password, tc.method))
			req := httptest.NewRequest("GET", "/metrics", nil)
			if tc.requestUser != "" || tc.requestPass != "" {
				req.SetBasicAuth(tc.requestUser, tc.requestPass)
			}
			w := httptest.NewRecorder()

			handler.ServeHTTP(w, req)

			assert.Equal(t, tc.expectedStatus, w.Code)
			if tc.expectedStatus == http.StatusOK {
				assert.Contains(t, w.Body.String(), "go_")
			} else {
				assert.Contains(t, w.Body.String(), "unauthorized")
			}
			assert.Equal(t, tc.expectedWWWAuth, w.Header().Get("WWW-Authenticate"))
		})
	}
}

func TestBearerToken(t *testing.T) {
	service := NewPromService(Options{Namespace: "test"})
	plainToken := testPlainToken

	bcryptHash, err := bcrypt.GenerateFromPassword([]byte(plainToken), bcrypt.DefaultCost)
	require.NoError(t, err)
	bcryptHashHex := hex.EncodeToString(bcryptHash)

	sha256Hash := sha256.Sum256([]byte(plainToken))
	sha256HashHex := hex.EncodeToString(sha256Hash[:])

	t.Run("case insensitive bearer scheme", func(t *testing.T) {
		handler := service.Handler(WithBearerToken(plainToken, HashingNone))
		testCases := []string{
			"Bearer " + plainToken,
			"bearer " + plainToken,
			"BEARER " + plainToken,
			"BeArEr " + plainToken,
			"bEaReR " + plainToken,
		}

		for _, authHeader := range testCases {
			t.Run(authHeader[:6], func(t *testing.T) {
				req := httptest.NewRequest("GET", "/metrics", nil)
				req.Header.Set("Authorization", authHeader)
				w := httptest.NewRecorder()

				handler.ServeHTTP(w, req)

				assert.Equal(t, http.StatusOK, w.Code)
				assert.Contains(t, w.Body.String(), "go_")
			})
		}
	})

	t.Run("unrelated schemes", func(t *testing.T) {
		handler := service.Handler(WithBearerToken(plainToken, HashingNone))
		testCases := []string{
			"Basic dXNlcjpwYXNz",
			"Digest username=\"user\"",
			"Custom token",
		}

		for _, authHeader := range testCases {
			t.Run(authHeader[:6], func(t *testing.T) {
				req := httptest.NewRequest("GET", "/metrics", nil)
				req.Header.Set("Authorization", authHeader)
				w := httptest.NewRecorder()

				handler.ServeHTTP(w, req)

				assert.Equal(t, http.StatusUnauthorized, w.Code)
				assert.Contains(t, w.Body.String(), "unauthorized")
				assert.Equal(t, `Bearer realm="metrics"`, w.Header().Get("WWW-Authenticate"))
			})
		}
	})

	testCases := []struct {
		name            string
		token           string
		authHeader      string
		expectedWWWAuth string
		method          hashingMethod
		expectedStatus  int
	}{
		{
			"plain - valid", plainToken, "Bearer " + plainToken, "",
			HashingNone, http.StatusOK,
		},
		{
			"plain - invalid", plainToken, "Bearer wrongtoken",
			`Bearer realm="metrics"`, HashingNone, http.StatusUnauthorized,
		},
		{
			"plain - no prefix", plainToken, plainToken,
			`Bearer realm="metrics"`, HashingNone, http.StatusUnauthorized,
		},
		{
			"plain - no header", plainToken, "",
			`Bearer realm="metrics"`, HashingNone, http.StatusUnauthorized,
		},
		{
			"plain - empty", plainToken, "Bearer ",
			`Bearer realm="metrics"`, HashingNone, http.StatusUnauthorized,
		},
		{
			"plain - extra spaces", plainToken, "Bearer  " + plainToken + "  ",
			"", HashingNone, http.StatusOK,
		},
		{
			"bcrypt - valid", bcryptHashHex, "Bearer " + plainToken, "",
			HashingBcrypt, http.StatusOK,
		},
		{
			"bcrypt - invalid", bcryptHashHex, "Bearer wrongtoken",
			`Bearer realm="metrics"`, HashingBcrypt, http.StatusUnauthorized,
		},
		{
			"bcrypt - no prefix", bcryptHashHex, plainToken,
			`Bearer realm="metrics"`, HashingBcrypt, http.StatusUnauthorized,
		},
		{
			"bcrypt - no header", bcryptHashHex, "",
			`Bearer realm="metrics"`, HashingBcrypt, http.StatusUnauthorized,
		},
		{
			"bcrypt - empty", bcryptHashHex, "Bearer ",
			`Bearer realm="metrics"`, HashingBcrypt, http.StatusUnauthorized,
		},
		{
			"bcrypt - invalid hex", "invalid-hex", "Bearer " + plainToken,
			`Bearer realm="metrics"`, HashingBcrypt, http.StatusUnauthorized,
		},
		{
			"sha256 - valid", sha256HashHex, "Bearer " + plainToken, "",
			HashingSHA256, http.StatusOK,
		},
		{
			"sha256 - invalid", sha256HashHex, "Bearer wrongtoken",
			`Bearer realm="metrics"`, HashingSHA256, http.StatusUnauthorized,
		},
		{
			"sha256 - no prefix", sha256HashHex, plainToken,
			`Bearer realm="metrics"`, HashingSHA256, http.StatusUnauthorized,
		},
		{
			"sha256 - no header", sha256HashHex, "",
			`Bearer realm="metrics"`, HashingSHA256, http.StatusUnauthorized,
		},
		{
			"sha256 - empty", sha256HashHex, "Bearer ",
			`Bearer realm="metrics"`, HashingSHA256, http.StatusUnauthorized,
		},
		{
			"sha256 - invalid hex", "invalid-hex-not-64-chars", "Bearer " + plainToken,
			`Bearer realm="metrics"`, HashingSHA256, http.StatusUnauthorized,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			handler := service.Handler(WithBearerToken(tc.token, tc.method))
			req := httptest.NewRequest("GET", "/metrics", nil)
			if tc.authHeader != "" {
				req.Header.Set("Authorization", tc.authHeader)
			}
			w := httptest.NewRecorder()

			handler.ServeHTTP(w, req)

			assert.Equal(t, tc.expectedStatus, w.Code)
			if tc.expectedStatus == http.StatusOK {
				assert.Contains(t, w.Body.String(), "go_")
			} else {
				assert.Contains(t, w.Body.String(), "unauthorized")
			}
			assert.Equal(t, tc.expectedWWWAuth, w.Header().Get("WWW-Authenticate"))
		})
	}
}

func TestHandlerNoAuth(t *testing.T) {
	service := NewPromService(Options{Namespace: "test"})
	handler := service.Handler()

	req := httptest.NewRequest("GET", "/metrics", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "go_")
}

func TestBothAuth(t *testing.T) {
	service := NewPromService(Options{Namespace: "test"})
	plainPassword := testPassword
	plainToken := testPlainToken
	username := testUsername

	bcryptHash, err := bcrypt.GenerateFromPassword([]byte(plainPassword), bcrypt.DefaultCost)
	require.NoError(t, err)
	bcryptHashHex := hex.EncodeToString(bcryptHash)

	sha256Hash := sha256.Sum256([]byte(plainPassword))
	sha256HashHex := hex.EncodeToString(sha256Hash[:])

	bcryptTokenHash, err := bcrypt.GenerateFromPassword([]byte(plainToken), bcrypt.DefaultCost)
	require.NoError(t, err)
	bcryptTokenHashHex := hex.EncodeToString(bcryptTokenHash)

	sha256TokenHash := sha256.Sum256([]byte(plainToken))
	sha256TokenHashHex := hex.EncodeToString(sha256TokenHash[:])

	combinations := []struct {
		name        string
		passValue   string
		tokenValue  string
		passMethod  hashingMethod
		tokenMethod hashingMethod
	}{
		{"plain password and plain token", plainPassword, plainToken, HashingNone, HashingNone},
		{"bcrypt hashed password and plain token", bcryptHashHex, plainToken, HashingBcrypt, HashingNone},
		{"plain password and sha256 hashed token", plainPassword, sha256TokenHashHex, HashingNone, HashingSHA256},
		{"sha256 hashed password and bcrypt hashed token", sha256HashHex, bcryptTokenHashHex, HashingSHA256, HashingBcrypt},
		{"bcrypt hashed password and bcrypt hashed token", bcryptHashHex, bcryptTokenHashHex, HashingBcrypt, HashingBcrypt},
		{"sha256 hashed password and sha256 hashed token", sha256HashHex, sha256TokenHashHex, HashingSHA256, HashingSHA256},
		{"bcrypt hashed password and sha256 hashed token", bcryptHashHex, sha256TokenHashHex, HashingBcrypt, HashingSHA256},
	}

	for _, combo := range combinations {
		t.Run(combo.name, func(t *testing.T) {
			handler := service.Handler(
				WithBasicAuth(username, combo.passValue, combo.passMethod),
				WithBearerToken(combo.tokenValue, combo.tokenMethod),
			)

			testCases := []struct {
				setup           func(*http.Request)
				name            string
				expectedWWWAuth string
				expectedStatus  int
			}{
				{
					name:            "valid basic auth",
					expectedStatus:  http.StatusOK,
					expectedWWWAuth: "",
					setup:           func(r *http.Request) { r.SetBasicAuth(username, plainPassword) },
				},
				{
					name:            "valid bearer token",
					expectedStatus:  http.StatusOK,
					expectedWWWAuth: "",
					setup:           func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+plainToken) },
				},
				{
					name:            "both invalid",
					expectedStatus:  http.StatusUnauthorized,
					expectedWWWAuth: `Basic realm="metrics"`,
					setup: func(r *http.Request) {
						r.SetBasicAuth(username, "wrongpass")
						r.Header.Set("Authorization", "Bearer wrongtoken")
					},
				},
				{
					name:            "no auth",
					expectedStatus:  http.StatusUnauthorized,
					expectedWWWAuth: `Basic realm="metrics"`,
					setup:           func(r *http.Request) {},
				},
			}

			for _, tc := range testCases {
				t.Run(tc.name, func(t *testing.T) {
					req := httptest.NewRequest("GET", "/metrics", nil)
					tc.setup(req)
					w := httptest.NewRecorder()

					handler.ServeHTTP(w, req)

					assert.Equal(t, tc.expectedStatus, w.Code)
					if tc.expectedStatus == http.StatusOK {
						assert.Contains(t, w.Body.String(), "go_")
					} else {
						assert.Contains(t, w.Body.String(), "unauthorized")
					}
					assert.Equal(t, tc.expectedWWWAuth, w.Header().Get("WWW-Authenticate"))
				})
			}
		})
	}
}

func TestConstantTimeComparison(t *testing.T) {
	plainToken := "testtoken"
	hash := sha256.Sum256([]byte(plainToken))
	hashedToken := hex.EncodeToString(hash[:])

	hash2 := sha256.Sum256([]byte(plainToken))
	hashedToken2 := hex.EncodeToString(hash2[:])

	assert.Equal(t, hashedToken, hashedToken2)

	differentToken := "differenttoken"
	hash3 := sha256.Sum256([]byte(differentToken))
	hashedToken3 := hex.EncodeToString(hash3[:])

	assert.NotEqual(t, hashedToken, hashedToken3)
}

func TestBcryptPasswordHashing(t *testing.T) {
	plainPassword := "mypassword"

	hashed1, err := bcrypt.GenerateFromPassword([]byte(plainPassword), bcrypt.DefaultCost)
	require.NoError(t, err)

	hashed2, err := bcrypt.GenerateFromPassword([]byte(plainPassword), bcrypt.DefaultCost)
	require.NoError(t, err)

	err1 := bcrypt.CompareHashAndPassword(hashed1, []byte(plainPassword))
	err2 := bcrypt.CompareHashAndPassword(hashed2, []byte(plainPassword))

	assert.NoError(t, err1)
	assert.NoError(t, err2)

	err3 := bcrypt.CompareHashAndPassword(hashed1, []byte("wrongpassword"))
	assert.Error(t, err3)
}

func TestGeneratePasswordHash(t *testing.T) {
	plainPassword := "testpassword123"

	hashedPasswordHex, err := generatePasswordHash(plainPassword)
	require.NoError(t, err)

	hashedPassword, err := hex.DecodeString(hashedPasswordHex)
	require.NoError(t, err)

	err = bcrypt.CompareHashAndPassword(hashedPassword, []byte(plainPassword))
	assert.NoError(t, err)

	err = bcrypt.CompareHashAndPassword(hashedPassword, []byte("wrongpassword"))
	assert.Error(t, err)
}

func TestGenerateTokenHash(t *testing.T) {
	plainToken := testPlainToken

	hashedToken := generateTokenHash(plainToken)

	_, err := hex.DecodeString(hashedToken)
	require.NoError(t, err)

	expectedHash := sha256.Sum256([]byte(plainToken))
	expectedHashHex := hex.EncodeToString(expectedHash[:])

	assert.Equal(t, expectedHashHex, hashedToken)

	differentToken := "differenttoken"
	differentHash := generateTokenHash(differentToken)
	assert.NotEqual(t, hashedToken, differentHash)
}

func TestAuthFallbackMatrix(t *testing.T) {
	service := NewPromService(Options{Namespace: "test"})
	username := testUsername
	password := testPassword
	token := "testtoken"

	bcryptPassHash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	require.NoError(t, err)
	bcryptPassHashHex := hex.EncodeToString(bcryptPassHash)

	sha256TokenHash := sha256.Sum256([]byte(token))
	sha256TokenHashHex := hex.EncodeToString(sha256TokenHash[:])

	testCases := []struct {
		handler         http.Handler
		requestSetup    func(*http.Request)
		authType        string
		name            string
		expectedWWWAuth string
		expectedStatus  int
	}{
		{
			name:            "only basic - no creds",
			expectedStatus:  http.StatusUnauthorized,
			authType:        "basic",
			expectedWWWAuth: `Basic realm="metrics"`,
			handler:         service.Handler(WithBasicAuth(username, password, HashingNone)),
			requestSetup:    func(r *http.Request) {},
		},
		{
			name:            "only basic - wrong creds",
			expectedStatus:  http.StatusUnauthorized,
			authType:        "basic",
			expectedWWWAuth: `Basic realm="metrics"`,
			handler:         service.Handler(WithBasicAuth(username, password, HashingNone)),
			requestSetup:    func(r *http.Request) { r.SetBasicAuth(username, "wrongpass") },
		},
		{
			name:            "only basic - right creds",
			expectedStatus:  http.StatusOK,
			authType:        "basic",
			expectedWWWAuth: "",
			handler:         service.Handler(WithBasicAuth(username, password, HashingNone)),
			requestSetup:    func(r *http.Request) { r.SetBasicAuth(username, password) },
		},
		{
			name:            "only basic - bearer token ignored",
			expectedStatus:  http.StatusUnauthorized,
			authType:        "basic",
			expectedWWWAuth: `Basic realm="metrics"`,
			handler:         service.Handler(WithBasicAuth(username, password, HashingNone)),
			requestSetup:    func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+token) },
		},
		{
			name:            "only bearer - no creds",
			expectedStatus:  http.StatusUnauthorized,
			authType:        "bearer",
			expectedWWWAuth: `Bearer realm="metrics"`,
			handler:         service.Handler(WithBearerToken(token, HashingNone)),
			requestSetup:    func(r *http.Request) {},
		},
		{
			name:            "only bearer - wrong token",
			expectedStatus:  http.StatusUnauthorized,
			authType:        "bearer",
			expectedWWWAuth: `Bearer realm="metrics"`,
			handler:         service.Handler(WithBearerToken(token, HashingNone)),
			requestSetup:    func(r *http.Request) { r.Header.Set("Authorization", "Bearer wrongtoken") },
		},
		{
			name:            "only bearer - right token",
			expectedStatus:  http.StatusOK,
			authType:        "bearer",
			expectedWWWAuth: "",
			handler:         service.Handler(WithBearerToken(token, HashingNone)),
			requestSetup:    func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+token) },
		},
		{
			name:            "only bearer - basic auth ignored",
			expectedStatus:  http.StatusUnauthorized,
			authType:        "bearer",
			expectedWWWAuth: `Bearer realm="metrics"`,
			handler:         service.Handler(WithBearerToken(token, HashingNone)),
			requestSetup:    func(r *http.Request) { r.SetBasicAuth(username, password) },
		},
		{
			name:            "both - no creds",
			expectedStatus:  http.StatusUnauthorized,
			authType:        "both",
			expectedWWWAuth: `Basic realm="metrics"`,
			handler: service.Handler(
				WithBasicAuth(username, password, HashingNone),
				WithBearerToken(token, HashingNone),
			),
			requestSetup: func(r *http.Request) {},
		},
		{
			name:            "both - wrong basic only",
			expectedStatus:  http.StatusUnauthorized,
			authType:        "both",
			expectedWWWAuth: `Basic realm="metrics"`,
			handler: service.Handler(
				WithBasicAuth(username, password, HashingNone),
				WithBearerToken(token, HashingNone),
			),
			requestSetup: func(r *http.Request) { r.SetBasicAuth(username, "wrongpass") },
		},
		{
			name:            "both - right basic",
			expectedStatus:  http.StatusOK,
			authType:        "both",
			expectedWWWAuth: "",
			handler: service.Handler(
				WithBasicAuth(username, password, HashingNone),
				WithBearerToken(token, HashingNone),
			),
			requestSetup: func(r *http.Request) { r.SetBasicAuth(username, password) },
		},
		{
			name:            "both - wrong bearer only",
			expectedStatus:  http.StatusUnauthorized,
			authType:        "both",
			expectedWWWAuth: `Basic realm="metrics"`,
			handler: service.Handler(
				WithBasicAuth(username, password, HashingNone),
				WithBearerToken(token, HashingNone),
			),
			requestSetup: func(r *http.Request) { r.Header.Set("Authorization", "Bearer wrongtoken") },
		},
		{
			name:            "both - right bearer",
			expectedStatus:  http.StatusOK,
			authType:        "both",
			expectedWWWAuth: "",
			handler: service.Handler(
				WithBasicAuth(username, password, HashingNone),
				WithBearerToken(token, HashingNone),
			),
			requestSetup: func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+token) },
		},
		{
			name:            "both - wrong basic + wrong bearer",
			expectedStatus:  http.StatusUnauthorized,
			authType:        "both",
			expectedWWWAuth: `Basic realm="metrics"`,
			handler: service.Handler(
				WithBasicAuth(username, password, HashingNone),
				WithBearerToken(token, HashingNone),
			),
			requestSetup: func(r *http.Request) {
				r.SetBasicAuth(username, "wrongpass")
				r.Header.Set("Authorization", "Bearer wrongtoken")
			},
		},
		{
			name:            "both hashed - right basic",
			expectedStatus:  http.StatusOK,
			authType:        "both",
			expectedWWWAuth: "",
			handler: service.Handler(
				WithBasicAuth(username, bcryptPassHashHex, HashingBcrypt),
				WithBearerToken(sha256TokenHashHex, HashingSHA256),
			),
			requestSetup: func(r *http.Request) { r.SetBasicAuth(username, password) },
		},
		{
			name:            "both hashed - right bearer",
			expectedStatus:  http.StatusOK,
			authType:        "both",
			expectedWWWAuth: "",
			handler: service.Handler(
				WithBasicAuth(username, bcryptPassHashHex, HashingBcrypt),
				WithBearerToken(sha256TokenHashHex, HashingSHA256),
			),
			requestSetup: func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+token) },
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/metrics", nil)
			tc.requestSetup(req)
			recorder := httptest.NewRecorder()

			tc.handler.ServeHTTP(recorder, req)

			assert.Equal(t, tc.expectedStatus, recorder.Code)
			if tc.expectedStatus == http.StatusOK {
				assert.Contains(t, recorder.Body.String(), "go_")
			} else {
				assert.Contains(t, recorder.Body.String(), "unauthorized")
			}

			if tc.expectedWWWAuth != "" {
				got := recorder.Header().Get("WWW-Authenticate")
				assert.Equal(t, tc.expectedWWWAuth, got)
			} else {
				got := recorder.Header().Get("WWW-Authenticate")
				assert.Empty(t, got)
			}
		})
	}
}

func TestCompareSecretExplicitly(t *testing.T) {
	plainSecret := "testsecret123"

	testCases := []struct {
		name     string
		provided string
		expected string
		method   hashingMethod
		want     bool
	}{
		{"bcrypt success", plainSecret, "", HashingBcrypt, true},
		{"bcrypt failure", "wrongsecret", "", HashingBcrypt, false},
		{"bcrypt invalid hex", plainSecret, "invalid-hex", HashingBcrypt, false},
		{"sha256 success", plainSecret, "", HashingSHA256, true},
		{"sha256 failure - wrong value", "wrongsecret", "", HashingSHA256, false},
		{"sha256 failure - invalid hex", plainSecret, "invalid-hex-not-64-chars", HashingSHA256, false},
		{"sha256 failure - wrong length hex", plainSecret, "abcd", HashingSHA256, false},
		{"plaintext success", plainSecret, plainSecret, HashingNone, true},
		{"plaintext failure", plainSecret, "different", HashingNone, false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var expected string
			if tc.expected != "" {
				expected = tc.expected
			} else {
				switch tc.method {
				case HashingBcrypt:
					hash, err := bcrypt.GenerateFromPassword([]byte(plainSecret), bcrypt.DefaultCost)
					require.NoError(t, err)
					expected = hex.EncodeToString(hash)
				case HashingSHA256:
					hash := sha256.Sum256([]byte(plainSecret))
					expected = hex.EncodeToString(hash[:])
				case HashingNone:
					expected = plainSecret
				}
			}

			result := compareSecret(tc.provided, expected, tc.method)
			assert.Equal(t, tc.want, result)
		})
	}

	t.Run("plaintext constant-time", func(t *testing.T) {
		secret1 := "secret123"
		secret2 := "secret124"

		result1 := compareSecret(secret1, secret1, HashingNone)
		result2 := compareSecret(secret1, secret2, HashingNone)

		assert.True(t, result1)
		assert.False(t, result2)
	})
}
