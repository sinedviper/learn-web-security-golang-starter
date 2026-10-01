package pawpal

import (
	"crypto/subtle"
	"fmt"
	"math"
)

type WebhookOutcome string

const (
	WebhookUnauthorized WebhookOutcome = "unauthorized"
	WebhookMalformed    WebhookOutcome = "malformed"
	WebhookApproved     WebhookOutcome = "approved"
)

const maxSafeInteger = 9_007_199_254_740_991

type WebhookVerification struct {
	Outcome WebhookOutcome
	OrderID int64
}

func CreateCheckoutURL(orderID int64) string {
	return fmt.Sprintf("https://pawpal.example/checkout?orderId=%d", orderID)
}

func VerifyWebhook(providedKey, expectedKey string, payload any) WebhookVerification {
	if len(providedKey) != len(expectedKey) || subtle.ConstantTimeCompare([]byte(providedKey), []byte(expectedKey)) != 1 {
		return WebhookVerification{Outcome: WebhookUnauthorized}
	}

	payloadRecord, ok := payload.(map[string]any)
	if !ok {
		return WebhookVerification{Outcome: WebhookMalformed}
	}

	orderIDValue, ok := payloadRecord["orderId"].(float64)
	if !ok || orderIDValue <= 0 || math.Trunc(orderIDValue) != orderIDValue || orderIDValue > maxSafeInteger {
		return WebhookVerification{Outcome: WebhookMalformed}
	}

	status, ok := payloadRecord["status"].(string)
	if !ok || status != "approved" {
		return WebhookVerification{Outcome: WebhookMalformed}
	}

	return WebhookVerification{Outcome: WebhookApproved, OrderID: int64(orderIDValue)}
}
