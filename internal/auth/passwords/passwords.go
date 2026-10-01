package passwords

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"
)

const (
	MaxLength = 128

	argon2idMemoryKiB   = 19 * 1024
	argon2idIterations  = 2
	argon2idParallelism = 1
	argon2idKeyLength   = 32
)

func Hash(password string) (string, error) {
	if utf8.RuneCountInString(password) > MaxLength {
		return "", fmt.Errorf("password exceeds maximum length of %d characters", MaxLength)
	}

	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}

	derivedKey := argon2.IDKey([]byte(password), salt, argon2idIterations, argon2idMemoryKiB, argon2idParallelism, argon2idKeyLength)

	return encodeArgon2idHash(argon2idHash{
		version:     argon2.Version,
		memoryKiB:   argon2idMemoryKiB,
		iterations:  argon2idIterations,
		parallelism: argon2idParallelism,
		salt:        salt,
		derivedKey:  derivedKey,
	}), nil
}

func Verify(password, encodedHash string) bool {
	if utf8.RuneCountInString(password) > MaxLength {
		return false
	}

	if parsed, ok := parseArgon2idHash(encodedHash); ok {
		if parsed.version != argon2.Version {
			return false
		}
		candidateKey := argon2.IDKey(
			[]byte(password),
			parsed.salt,
			parsed.iterations,
			parsed.memoryKiB,
			parsed.parallelism,
			uint32(len(parsed.derivedKey)),
		)
		return subtle.ConstantTimeCompare(candidateKey, parsed.derivedKey) == 1
	}

	legacyHash, ok := decodeLegacyHash(encodedHash)
	if !ok {
		return false
	}
	candidateHash := sha256.Sum256([]byte(password))
	return subtle.ConstantTimeCompare(candidateHash[:], legacyHash) == 1
}

func NeedsRehash(encodedHash string) bool {
	parsed, ok := parseArgon2idHash(encodedHash)
	if !ok {
		_, legacyOK := decodeLegacyHash(encodedHash)
		return legacyOK
	}

	return parsed.version != argon2.Version ||
		parsed.memoryKiB != argon2idMemoryKiB ||
		parsed.iterations != argon2idIterations ||
		parsed.parallelism != argon2idParallelism ||
		uint32(len(parsed.derivedKey)) != argon2idKeyLength
}
