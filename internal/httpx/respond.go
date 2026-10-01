package httpx

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"github.com/bootdotdev/learn-web-security/internal/templates"
	"github.com/bootdotdev/learn-web-security/internal/textutils"
)

func RespondWithError(responseWriter http.ResponseWriter, code int, message string) {
	message = textutils.StripANSI(message)
	if code >= 500 {
		fmt.Println(message)
		message = "The request failed. Try again, or return to the store."
	}
	RespondWithJSON(responseWriter, code, map[string]string{"error": message})
}

func RespondWithJSON(responseWriter http.ResponseWriter, code int, payload any) {
	responseWriter.Header().Set("Content-Type", "application/json")
	responseWriter.WriteHeader(code)
	encoder := json.NewEncoder(responseWriter)
	if err := encoder.Encode(payload); err != nil {
		log.Printf("Error respondWithJSON: status code %v: %v", code, err)
	}
}

func RespondWithErrorPage(responseWriter http.ResponseWriter, renderer *templates.Renderer, statusCode int, title, message string) error {
	if statusCode >= 500 {
		title = "Something Went Wrong"
		message = "The request failed. Try again, or return to the store."
	}
	return renderer.Render(responseWriter, statusCode, "error", templates.ErrorPage{
		Title:      title,
		StatusCode: statusCode,
		Message:    message,
	})
}
