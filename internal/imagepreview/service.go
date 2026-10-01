package imagepreview

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type Result struct {
	RequestedURL string
	FinalURL     string
	Status       int
	ContentType  string
	ByteLength   int64
	ImageDataURL string
}

type Error struct {
	Message string
}

func (err *Error) Error() string {
	return err.Message
}

type client interface {
	Do(*http.Request) (*http.Response, error)
}

type Service struct {
	client client
}

func NewService() *Service {
	transport := &http.Transport{
		Proxy:                 nil,
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: 5 * time.Second,
	}
	httpClient := &http.Client{
		Timeout:   5 * time.Second,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	return &Service{client: httpClient}
}

func (service *Service) Fetch(ctx context.Context, rawURL string, maxBytes int64) (Result, error) {
	requestedURL, valid := allowedURL(rawURL)
	if !valid {
		return Result{}, &Error{Message: "Use an HTTPS URL from an allowed image host."}
	}
	if maxBytes <= 0 {
		return Result{}, errors.New("maximum image size must be positive")
	}
	requestContext, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(requestContext, http.MethodGet, requestedURL.String(), nil)
	if err != nil {
		return Result{}, &Error{Message: "Use an absolute HTTP or HTTPS URL."}
	}
	response, err := service.client.Do(request)
	if err != nil {
		if errors.Is(requestContext.Err(), context.DeadlineExceeded) {
			return Result{}, &Error{Message: "The image host did not respond in time."}
		}
		return Result{}, &Error{Message: "The image host could not be reached."}
	}
	defer response.Body.Close()
	if response.StatusCode >= http.StatusMultipleChoices && response.StatusCode < http.StatusBadRequest {
		return Result{}, &Error{Message: "Image URL redirects are not allowed."}
	}
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return Result{}, &Error{Message: fmt.Sprintf("The image host returned HTTP %d.", response.StatusCode)}
	}
	declaredContentType := strings.ToLower(strings.TrimSpace(strings.Split(response.Header.Get("Content-Type"), ";")[0]))
	if !strings.HasPrefix(declaredContentType, "image/") {
		return Result{}, &Error{Message: "The URL did not return an image."}
	}
	if declaredLength, validLength := declaredContentLength(response.Header.Get("Content-Length")); validLength && declaredLength > float64(maxBytes) {
		return Result{}, &Error{Message: "The image is larger than 1 MiB."}
	}
	imageBytes, err := readImageBytes(response.Body, maxBytes)
	if err != nil {
		return Result{}, err
	}
	detectedContentType, validImage := detectImageContentType(imageBytes)
	if !validImage || detectedContentType != declaredContentType {
		return Result{}, &Error{Message: "The response is not a valid PNG, JPEG, or WebP image."}
	}
	finalURL := requestedURL.String()
	if response.Request != nil && response.Request.URL != nil {
		finalURL = response.Request.URL.String()
	}
	return Result{
		RequestedURL: requestedURL.String(), FinalURL: finalURL, Status: response.StatusCode, ContentType: detectedContentType,
		ByteLength: int64(len(imageBytes)), ImageDataURL: "data:" + detectedContentType + ";base64," + base64.StdEncoding.EncodeToString(imageBytes),
	}, nil
}

func allowedURL(rawURL string) (*url.URL, bool) {
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Host != "storage.googleapis.com" || parsed.Scheme != "https" || parsed.User != nil {
		return nil, false
	}

	if parsed.Path == "" {
		parsed.Path = "/"
	}
	return parsed, true
}

func declaredContentLength(value string) (float64, bool) {
	length, err := strconv.ParseFloat(strings.TrimSpace(value), 64)
	if err != nil || math.IsNaN(length) || math.IsInf(length, 0) {
		return 0, false
	}
	return length, true
}

func readImageBytes(responseBody io.Reader, maxBytes int64) ([]byte, error) {
	imageBytes, err := io.ReadAll(io.LimitReader(responseBody, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(imageBytes)) > maxBytes {
		return nil, &Error{Message: "The image is larger than 1 MiB."}
	}
	if len(imageBytes) == 0 {
		return nil, &Error{Message: "The image response was empty."}
	}
	return imageBytes, nil
}

func detectImageContentType(imageBytes []byte) (string, bool) {
	if len(imageBytes) >= 8 && bytes.Equal(imageBytes[:8], []byte{0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a}) {
		return "image/png", true
	}
	if len(imageBytes) >= 3 && bytes.Equal(imageBytes[:3], []byte{0xff, 0xd8, 0xff}) {
		return "image/jpeg", true
	}
	if len(imageBytes) >= 12 && bytes.Equal(imageBytes[:4], []byte("RIFF")) && bytes.Equal(imageBytes[8:12], []byte("WEBP")) {
		return "image/webp", true
	}
	return "", false
}
