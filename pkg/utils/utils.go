package utils

import (
	"authinticator/internal/otpauthpb"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"net/url"
	"strings"
	"time"

	"encoding/base32"

	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"io"

	"github.com/pquerna/otp/totp"
	"google.golang.org/protobuf/proto"
)

func VerifySignedCookie(cookieValue, secret string) (string, bool) {
	decoded, err := url.QueryUnescape(cookieValue)
	if err != nil {
		return "", false
	}
	parts := strings.SplitN(decoded, ".", 2)
	if len(parts) != 2 {
		return "", false
	}
	value, sig := parts[0], parts[1]
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(value))
	expectedSig := base64.StdEncoding.EncodeToString(h.Sum(nil))
	if hmac.Equal([]byte(sig), []byte(expectedSig)) {
		return value, true
	}
	return "", false
}

func GetUserIDFromToken(ctx context.Context, db *sql.DB, token string) (string, error) {
	var userID string
	err := db.QueryRowContext(ctx, "SELECT user_id FROM session WHERE token = $1", token).Scan(&userID)
	if err != nil {
		return "", err
	}
	return userID, nil
}

func ExtractTOTPSecret(key string) string {
	key = strings.TrimSpace(key)
	if strings.HasPrefix(key, "otpauth://") {
		u, err := url.Parse(key)
		if err == nil {
			secret := u.Query().Get("secret")
			return strings.ToUpper(secret)
		}
	}
	return strings.ToUpper(strings.ReplaceAll(key, " ", ""))
}

func ValidateTOTPSecret(secret string) bool {
	_, err := totp.GenerateCode(secret, time.Now())
	return err == nil
}

// ExtractSecretsFromMigrationURL parses an otpauth-migration URL and returns a slice of (name, secret) pairs.
func ExtractSecretsFromMigrationURL(urlStr string) ([][2]string, error) {
	const prefix = "otpauth-migration://offline?data="
	if !strings.HasPrefix(urlStr, prefix) {
		return nil, nil
	}
	dataPart := strings.TrimPrefix(urlStr, prefix)
	b, err := base64.StdEncoding.DecodeString(dataPart)
	if err != nil {
		return nil, err
	}
	var payload otpauthpb.MigrationPayload
	if err := proto.Unmarshal(b, &payload); err != nil {
		return nil, err
	}
	var results [][2]string
	for _, param := range payload.OtpParameters {
		// Secret is []byte, encode as base32 (uppercase, no padding)
		secret := strings.ToUpper(base32NoPadEncode(param.Secret))
		results = append(results, [2]string{param.Name, secret})
	}
	return results, nil
}

// ExtractServiceNamesFromMigrationURL returns a slice of service names from an otpauth-migration URL.
func ExtractServiceNamesFromMigrationURL(urlStr string) ([]string, error) {
	const prefix = "otpauth-migration://offline?data="
	if !strings.HasPrefix(urlStr, prefix) {
		return nil, nil
	}
	dataPart := strings.TrimPrefix(urlStr, prefix)
	b, err := base64.StdEncoding.DecodeString(dataPart)
	if err != nil {
		return nil, err
	}
	var payload otpauthpb.MigrationPayload
	if err := proto.Unmarshal(b, &payload); err != nil {
		return nil, err
	}
	var services []string
	for _, param := range payload.OtpParameters {
		services = append(services, param.Issuer)
	}
	return services, nil
}

// ExtractServiceNameFromKey extracts the service name (issuer) from an otpauth URL, or returns empty string if not found.
func ExtractServiceNameFromKey(key string) string {
	key = strings.TrimSpace(key)
	if strings.HasPrefix(key, "otpauth://") {
		u, err := url.Parse(key)
		if err == nil {
			return u.Query().Get("issuer")
		}
	}
	return ""
}

// base32NoPadEncode encodes bytes to base32, no padding, uppercase
func base32NoPadEncode(b []byte) string {
	enc := base32.StdEncoding.WithPadding(base32.NoPadding)
	return enc.EncodeToString(b)
}

func EncryptKey(plain, salt string) (string, error) {
	hash := sha256.Sum256([]byte(salt))
	block, err := aes.NewCipher(hash[:])
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	ciphertext := gcm.Seal(nonce, nonce, []byte(plain), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func DecryptKey(ciphertextB64, salt string) (string, error) {
	hash := sha256.Sum256([]byte(salt))
	block, err := aes.NewCipher(hash[:])
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	ciphertext, err := base64.StdEncoding.DecodeString(ciphertextB64)
	if err != nil {
		return "", err
	}
	if len(ciphertext) < gcm.NonceSize() {
		return "", errors.New("ciphertext too short")
	}
	nonce := ciphertext[:gcm.NonceSize()]
	ciphertext = ciphertext[gcm.NonceSize():]
	plain, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}
	return string(plain), nil
}

func GenerateMigrationURL(pairs [][2]string) (string, error) {
	var params []*otpauthpb.OTPParameters
	for _, pair := range pairs {
		name, secret := pair[0], pair[1]
		secretBytes, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(secret))
		if err != nil {
			continue
		}
		params = append(params, &otpauthpb.OTPParameters{
			Secret:    secretBytes,
			Name:      name,
			Issuer:    "",
			Algorithm: otpauthpb.Algorithm_ALGORITHM_SHA1,
			Digits:    otpauthpb.DigitCount_DIGIT_COUNT_SIX,
			Type:      otpauthpb.OTPType_OTP_TYPE_TOTP,
			Counter:   0,
		})
	}
	if len(params) == 0 {
		return "", errors.New("no valid secrets")
	}
	payload := &otpauthpb.MigrationPayload{
		OtpParameters: params,
		Version:       1,
	}
	b, err := proto.Marshal(payload)
	if err != nil {
		return "", err
	}
	data := base64.StdEncoding.EncodeToString(b)
	return "otpauth-migration://offline?data=" + data, nil
}
