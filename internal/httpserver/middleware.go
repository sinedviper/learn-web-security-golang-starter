//lint:file-ignore U1000 Some code in this file is used later

package httpserver

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"math"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
	"uuid"

	"github.com/bootdotdev/learn-web-security/internal/httpx"
	"github.com/bootdotdev/learn-web-security/internal/logging"
	"github.com/bootdotdev/learn-web-security/internal/templates"
)

type middleware func(http.Handler) http.Handler

func applyMiddleware(handler http.Handler, middlewareChain ...middleware) http.Handler {
	for _, currentMiddleware := range slices.Backward(middlewareChain) {
		handler = currentMiddleware(handler)
	}
	return handler
}

// publicProductsCORS allows any origin to read the public product catalog
// over CORS, without credentials. It must only ever wrap GET /api/products.
func publicProductsCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(responseWriter http.ResponseWriter, request *http.Request) {
		responseWriter.Header().Set("Access-Control-Allow-Origin", "*")
		next.ServeHTTP(responseWriter, request)
	})
}

// publicProductsPreflight answers the CORS preflight for GET /api/products.
// It allows any origin and only the GET method, with no credentials and no
// request headers beyond the browser-controlled defaults.
func publicProductsPreflight(responseWriter http.ResponseWriter, _ *http.Request) {
	responseWriter.Header().Set("Access-Control-Allow-Origin", "*")
	responseWriter.Header().Set("Access-Control-Allow-Methods", "GET")
	//responseWriter.Header().Set("Access-Control-Allow-Headers", "")
	responseWriter.WriteHeader(http.StatusNoContent)
}

func requestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(responseWriter http.ResponseWriter, request *http.Request) {
		id := uuid.NewV4()
		responseWriter.Header().Set("X-Request-ID", id.String())
		request = request.WithContext(httpx.WithRequestID(request.Context(), id))
		next.ServeHTTP(responseWriter, request)
	})
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(responseWriter http.ResponseWriter, request *http.Request) {
		nonce := httpx.CSPNonce(request.Context())
		csp := fmt.Sprintf(
			"frame-ancestors 'self'; default-src 'self'; script-src 'self' 'nonce-%s'; style-src 'self'; img-src 'self' data:; frame-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'",
			nonce,
		)
		header := responseWriter.Header()
		header.Set("Content-Security-Policy", csp)
		header.Set("Referrer-Policy", "strict-origin-when-cross-origin")
		header.Set("X-Content-Type-Options", "nosniff")
		header.Set("X-Frame-Options", "SAMEORIGIN")
		header.Set("Cross-Origin-Opener-Policy", "same-origin")
		header.Set("Cross-Origin-Resource-Policy", "same-origin")
		header.Set("Origin-Agent-Cluster", "?1")
		header.Set("X-DNS-Prefetch-Control", "off")
		header.Set("X-Download-Options", "noopen")
		header.Set("X-Permitted-Cross-Domain-Policies", "none")
		header.Set("X-XSS-Protection", "0")
		next.ServeHTTP(responseWriter, request)
	})
}

func crossOriginResourcePolicy(policy string) middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(responseWriter http.ResponseWriter, request *http.Request) {
			responseWriter.Header().Set("Cross-Origin-Resource-Policy", policy)
			next.ServeHTTP(responseWriter, request)
		})
	}
}

func cspNonce(next http.Handler) http.Handler {
	return http.HandlerFunc(func(responseWriter http.ResponseWriter, request *http.Request) {
		nonceBytes := make([]byte, 16)
		if _, err := rand.Read(nonceBytes); err != nil {
			http.Error(responseWriter, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		nonce := base64.StdEncoding.EncodeToString(nonceBytes)
		request = request.WithContext(httpx.WithCSPNonce(request.Context(), nonce))
		next.ServeHTTP(responseWriter, request)
	})
}

func recoverPanics(logger *logging.Logger, renderer *templates.Renderer) middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(responseWriter http.ResponseWriter, request *http.Request) {
			defer func() {
				if recovered := recover(); recovered != nil {
					_ = logger.Event("unhandled_error", map[string]any{
						"method":  request.Method,
						"path":    request.URL.Path,
						"message": fmt.Sprint(recovered),
					})
					if err := httpx.RespondWithErrorPage(responseWriter, renderer, http.StatusInternalServerError, "Unhandled Error", fmt.Sprint(recovered)); err != nil {
						http.Error(responseWriter, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
					}
				}
			}()
			next.ServeHTTP(responseWriter, request)
		})
	}
}

func LoadShedder(maxInFlight int, retryAfterSeconds int) func(http.Handler) http.Handler {
	if maxInFlight <= 0 {
		panic("load shedder max in-flight must be positive")
	}
	if retryAfterSeconds <= 0 {
		panic("load shedder retry-after must be positive")
	}
	slots := make(chan struct{}, maxInFlight)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(responseWriter http.ResponseWriter, request *http.Request) {
			responseWriter.Header().Set("X-In-Flight-Limit", strconv.Itoa(maxInFlight))
			select {
			case slots <- struct{}{}:
			default:
				responseWriter.Header().Set("Retry-After", strconv.Itoa(retryAfterSeconds))
				httpx.RespondWithJSON(responseWriter, http.StatusServiceUnavailable, map[string]string{"error": "Service is at capacity"})
				return
			}
			defer func() { <-slots }()
			next.ServeHTTP(responseWriter, request)
		})
	}
}

func SearchThrottle(renderer *templates.Renderer) func(http.Handler) http.Handler {
	return fixedWindowRateLimiter(rateLimitOptions{
		window:  time.Second,
		maximum: 5,
		key:     sharedRateLimitKey,
		onLimit: func(responseWriter http.ResponseWriter, request *http.Request, _ rateLimitState) {
			if err := httpx.RespondWithErrorPage(responseWriter, renderer, http.StatusTooManyRequests, "Search Is Busy", "Try again shortly."); err != nil {
				http.Error(responseWriter, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			}
		},
	})
}

func sharedRateLimitKey(*http.Request) string {
	return "search"
}

type rateLimitCounter struct {
	count   int
	resetAt time.Time
}

type rateLimitOptions struct {
	window  time.Duration
	maximum int
	key     func(*http.Request) string
	onLimit func(http.ResponseWriter, *http.Request, rateLimitState)
	now     func() time.Time
}

type rateLimitState struct {
	limit             int
	remaining         int
	resetAt           time.Time
	retryAfterSeconds int
}

type fixedWindowLimiter struct {
	options       rateLimitOptions
	counters      map[string]rateLimitCounter
	countersMutex sync.Mutex
	nextSweepAt   time.Time
}

func newFixedWindowLimiter(options rateLimitOptions) *fixedWindowLimiter {
	validateRateLimitOptions(options)
	if options.now == nil {
		options.now = time.Now
	}
	if options.key == nil {
		options.key = clientIPKey
	}
	return &fixedWindowLimiter{
		options:     options,
		counters:    make(map[string]rateLimitCounter),
		nextSweepAt: options.now().Add(options.window),
	}
}

func validateRateLimitOptions(options rateLimitOptions) {
	if options.window <= 0 {
		panic("rate-limit window must be positive")
	}
	if options.maximum <= 0 {
		panic("rate-limit maximum must be positive")
	}
}

func (limiter *fixedWindowLimiter) consume(request *http.Request) (rateLimitState, bool) {
	now := limiter.options.now()
	key := limiter.options.key(request)

	limiter.countersMutex.Lock()
	defer limiter.countersMutex.Unlock()
	limiter.sweepExpiredCounters(now)

	counter, exists := limiter.counters[key]
	if !exists || !now.Before(counter.resetAt) {
		counter = rateLimitCounter{resetAt: now.Add(limiter.options.window)}
	}
	retryAfterSeconds := max(1, int(math.Ceil(counter.resetAt.Sub(now).Seconds())))
	if counter.count >= limiter.options.maximum {
		return rateLimitState{
			limit:             limiter.options.maximum,
			remaining:         0,
			resetAt:           counter.resetAt,
			retryAfterSeconds: retryAfterSeconds,
		}, true
	}

	counter.count++
	limiter.counters[key] = counter
	return rateLimitState{
		limit:             limiter.options.maximum,
		remaining:         limiter.options.maximum - counter.count,
		resetAt:           counter.resetAt,
		retryAfterSeconds: retryAfterSeconds,
	}, false
}

func (limiter *fixedWindowLimiter) sweepExpiredCounters(now time.Time) {
	if now.Before(limiter.nextSweepAt) {
		return
	}
	for counterKey, counter := range limiter.counters {
		if !now.Before(counter.resetAt) {
			delete(limiter.counters, counterKey)
		}
	}
	limiter.nextSweepAt = now.Add(limiter.options.window)
}

func (limiter *fixedWindowLimiter) reject(responseWriter http.ResponseWriter, request *http.Request, state rateLimitState) {
	setRateLimitHeaders(responseWriter, state)
	responseWriter.Header().Set("Retry-After", strconv.Itoa(state.retryAfterSeconds))
	if limiter.options.onLimit != nil {
		limiter.options.onLimit(responseWriter, request, state)
		return
	}
	httpx.RespondWithJSON(responseWriter, http.StatusTooManyRequests, map[string]string{"error": "Too many requests"})
}

func fixedWindowRateLimiter(options rateLimitOptions) middleware {
	limiter := newFixedWindowLimiter(options)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(responseWriter http.ResponseWriter, request *http.Request) {
			state, limited := limiter.consume(request)
			if limited {
				limiter.reject(responseWriter, request, state)
				return
			}
			setRateLimitHeaders(responseWriter, state)
			next.ServeHTTP(responseWriter, request)
		})
	}
}

func setRateLimitHeaders(responseWriter http.ResponseWriter, state rateLimitState) {
	responseWriter.Header().Set("RateLimit-Limit", strconv.Itoa(state.limit))
	responseWriter.Header().Set("RateLimit-Remaining", strconv.Itoa(state.remaining))
	responseWriter.Header().Set("RateLimit-Reset", strconv.FormatInt(state.resetAt.Unix()+boolToInt64(state.resetAt.Nanosecond() > 0), 10))
}

func clientIPKey(request *http.Request) string {
	host, _, err := net.SplitHostPort(request.RemoteAddr)
	if err == nil && host != "" {
		return host
	}
	if request.RemoteAddr != "" {
		return request.RemoteAddr
	}
	return "unknown"
}

func clientIPKeyWithTrustedProxies(trustedProxyHops int) func(*http.Request) string {
	return func(request *http.Request) string {
		if trustedProxyHops > 0 {
			forwardedAddresses := strings.Split(request.Header.Get("X-Forwarded-For"), ",")
			selectedIndex := len(forwardedAddresses) - trustedProxyHops
			if selectedIndex >= 0 && selectedIndex < len(forwardedAddresses) {
				if selectedAddress := strings.TrimSpace(forwardedAddresses[selectedIndex]); selectedAddress != "" {
					return selectedAddress
				}
			}
		}
		return clientIPKey(request)
	}
}

func checkOrigin(appOrigin string, renderer *templates.Renderer) middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(responseWriter http.ResponseWriter, request *http.Request) {
			if request.Method != http.MethodPost {
				next.ServeHTTP(responseWriter, request)
				return
			}
			origin := request.Header.Get("Origin")
			if origin == "" {
				if referer := request.Header.Get("Referer"); referer != "" {
					if parsed, err := url.Parse(referer); err == nil {
						origin = parsed.Scheme + "://" + parsed.Host
					}
				}
			}
			if origin != appOrigin {
				if err := httpx.RespondWithErrorPage(responseWriter, renderer, http.StatusForbidden, "Forbidden", "Cross-site request blocked."); err != nil {
					http.Error(responseWriter, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				}
				return
			}
			next.ServeHTTP(responseWriter, request)
		})
	}
}

func boolToInt64(value bool) int64 {
	if value {
		return 1
	}
	return 0
}
