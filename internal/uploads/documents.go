//lint:file-ignore U1000 Some code in this file is used later

package uploads

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"uuid"
)

type Keyring interface {
	Encrypt([]byte) (string, error)
	Decrypt(string) ([]byte, error)
}

type StoredDocument struct {
	ContentType string
	StoragePath string
}

func StoreDocument(contents []byte, uploadDirectory string, encryptionKeyring Keyring) (StoredDocument, bool, error) {
	mimeType, extension, valid := detectDocumentType(contents)
	if !valid {
		return StoredDocument{}, false, nil
	}
	storedContents, encrypted, err := encryptDocument(contents, encryptionKeyring)
	if err != nil {
		return StoredDocument{}, false, err
	}
	if err := os.MkdirAll(uploadDirectory, 0o755); err != nil {
		return StoredDocument{}, false, fmt.Errorf("create upload directory: %w", err)
	}
	storagePath := filepath.Join(uploadDirectory, uuid.NewV4().String()+extension)
	if encrypted {
		storagePath += ".enc"
	}
	if err := writeDocument(storagePath, storedContents, encrypted); err != nil {
		return StoredDocument{}, false, err
	}
	return StoredDocument{ContentType: mimeType, StoragePath: storagePath}, true, nil
}

func detectDocumentType(contents []byte) (string, string, bool) {
	if len(contents) >= 5 && string(contents[:5]) == "%PDF-" {
		return "application/pdf", ".pdf", true
	}
	if len(contents) >= 3 && contents[0] == 0xff && contents[1] == 0xd8 && contents[2] == 0xff {
		return "image/jpeg", ".jpg", true
	}
	if len(contents) >= 8 && string(contents[:8]) == "\x89PNG\r\n\x1a\n" {
		return "image/png", ".png", true
	}
	if len(contents) >= 12 && string(contents[:4]) == "RIFF" && string(contents[8:12]) == "WEBP" {
		return "image/webp", ".webp", true
	}
	return "", "", false
}

func encryptDocument(contents []byte, encryptionKeyring Keyring) (string, bool, error) {
	serialized, err := encryptionKeyring.Encrypt(contents)
	if err != nil {
		return "", false, fmt.Errorf("encrypt tax document: %w", err)
	}
	return serialized, true, nil
}

func decryptDocument(storedContents string, encryptionKeyring Keyring) ([]byte, error) {
	contents, err := encryptionKeyring.Decrypt(storedContents)
	if err != nil {
		return nil, fmt.Errorf("decrypt tax document: %w", err)
	}
	return contents, nil
}

func writeDocument(storagePath, storedContents string, encrypted bool) error {
	fileMode := os.FileMode(0o644)
	fileFlags := os.O_WRONLY | os.O_CREATE | os.O_TRUNC
	if encrypted {
		fileMode = 0o600
		fileFlags = os.O_WRONLY | os.O_CREATE | os.O_EXCL
	}
	file, err := os.OpenFile(storagePath, fileFlags, fileMode)
	if err != nil {
		return fmt.Errorf("write tax document: %w", err)
	}
	_, writeErr := file.WriteString(storedContents)
	closeErr := file.Close()
	if writeErr != nil {
		_ = RemoveDocument(storagePath)
		return fmt.Errorf("write tax document: %w", writeErr)
	}
	if closeErr != nil {
		_ = RemoveDocument(storagePath)
		return fmt.Errorf("write tax document: %w", closeErr)
	}
	return nil
}

func ReadDocument(storagePath string, encryptionKeyring Keyring) ([]byte, error) {
	storedContents, err := os.ReadFile(storagePath)
	if err != nil {
		return nil, fmt.Errorf("read tax document: %w", err)
	}
	return decryptDocument(string(storedContents), encryptionKeyring)
}

func RemoveDocument(storagePath string) error {
	if err := os.Remove(storagePath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove tax document: %w", err)
	}
	return nil
}
