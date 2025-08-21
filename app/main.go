package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	client               *http.Client
	baseURL              string
	username             string
	password             string
	authToken            string
	debug                bool
	cache                TorrentSummary
	cacheMutex           sync.RWMutex
	cacheExpiry          time.Time
	loginAttempts        int
	loginBlockedUntil    time.Time
	loginMutex           sync.Mutex
	rateLimitRequests    int
	rateLimitMutex       sync.Mutex
	rateLimitWindow      time.Time
	rateLimitPerMinute   int
	cacheDurationMinutes int
)

type TorrentInfo struct {
	Name       string  `json:"name"`
	Category   string  `json:"category"`
	NumLeechs  int     `json:"num_leechs"`
	NumSeeds   int     `json:"num_seeds"`
	Progress   float64 `json:"progress"`
	State      string  `json:"state"`
	Size       int64   `json:"size"`
	Downloaded int64   `json:"downloaded"`
	ETA        int64   `json:"eta"`
}

type TorrentSummary struct {
	TotalDownloadSpeed float64       `json:"total_download_speed"`
	SeedingCount       int           `json:"seeding_count"`
	LeechingCount      int           `json:"leeching_count"`
	Torrents           []TorrentInfo `json:"torrents"`
}

func debugLog(format string, args ...interface{}) {
	if debug {
		log.Printf("[DEBUG] "+format, args...)
	}
}

func initRateLimit() {
	rateLimitStr := os.Getenv("RATE_LIMIT")
	if rateLimitStr == "" {
		rateLimitPerMinute = 10
	} else {
		limit, err := strconv.Atoi(rateLimitStr)
		if err != nil {
			log.Printf("Invalid RATE_LIMIT value '%s', using default 10", rateLimitStr)
			rateLimitPerMinute = 10
		} else {
			rateLimitPerMinute = limit
		}
	}

	rateLimitWindow = time.Now().Add(time.Minute)
	rateLimitRequests = 0
	log.Printf("Rate limit initialized: %d requests per minute", rateLimitPerMinute)
}

func checkRateLimit() bool {
	rateLimitMutex.Lock()
	defer rateLimitMutex.Unlock()

	now := time.Now()
	if now.After(rateLimitWindow) {
		rateLimitRequests = 0
		rateLimitWindow = now.Add(time.Minute)
		debugLog("Rate limit window reset")
	}

	if rateLimitRequests >= rateLimitPerMinute {
		remainingTime := time.Until(rateLimitWindow)
		debugLog("Rate limit exceeded, remaining time: %v", remainingTime.Round(time.Second))
		return false
	}

	rateLimitRequests++
	debugLog("Rate limit check passed, request %d/%d", rateLimitRequests, rateLimitPerMinute)
	return true
}

func login() error {
	loginMutex.Lock()
	defer loginMutex.Unlock()

	debugLog("Login attempt started, current attempts: %d", loginAttempts)

	if time.Now().Before(loginBlockedUntil) {
		remainingTime := time.Until(loginBlockedUntil)
		debugLog("Login blocked, remaining time: %v", remainingTime.Round(time.Minute))
		return fmt.Errorf("login blocked for %v due to repeated failures", remainingTime.Round(time.Minute))
	}

	jar, _ := cookiejar.New(nil)
	client = &http.Client{Jar: jar}

	form := url.Values{}
	form.Add("username", username)
	form.Add("password", password)

	loginURL := strings.TrimRight(baseURL, "/") + "/api/v2/auth/login"
	debugLog("Attempting login to: %s", loginURL)
	debugLog("Login user: %s", username)

	resp, err := client.PostForm(loginURL, form)
	if err != nil {
		loginAttempts++
		debugLog("Login network error, attempt %d/3: %v", loginAttempts, err)
		if loginAttempts >= 3 {
			loginBlockedUntil = time.Now().Add(30 * time.Minute)
			debugLog("Maximum login attempts reached, blocking until: %v", loginBlockedUntil)
			log.Printf("Login failed %d times, blocking for 30 minutes until %v", loginAttempts, loginBlockedUntil)
			loginAttempts = 0
			return fmt.Errorf("login blocked for 30 minutes due to repeated failures")
		}
		return fmt.Errorf("login failed: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	debugLog("Login response status: %s", resp.Status)
	debugLog("Login response body: %s", string(body))

	if string(body) != "Ok." {
		loginAttempts++
		debugLog("Login authentication failed, attempt %d/3: %s", loginAttempts, string(body))
		if loginAttempts >= 3 {
			loginBlockedUntil = time.Now().Add(30 * time.Minute)
			debugLog("Maximum login attempts reached, blocking until: %v", loginBlockedUntil)
			log.Printf("Login failed %d times, blocking for 30 minutes until %v", loginAttempts, loginBlockedUntil)
			loginAttempts = 0
			return fmt.Errorf("login blocked for 30 minutes due to repeated failures")
		}
		return fmt.Errorf("login failed, response: %s", body)
	}

	if loginAttempts > 0 {
		debugLog("Login successful, resetting attempt counter from %d to 0", loginAttempts)
	}
	loginAttempts = 0
	log.Println("qBittorrent login successful")
	return nil
}

var errUnauthorized = fmt.Errorf("unauthorized")

func fetchTorrents() (TorrentSummary, error) {
	torrents, err := fetchTorrentsOnce()
	if err == errUnauthorized {
		log.Println("Session expired, re-logging in...")
		if err = login(); err != nil {
			return TorrentSummary{}, err
		}
		torrents, err = fetchTorrentsOnce()
	}
	return torrents, err
}

func fetchTorrentsOnce() (TorrentSummary, error) {
	req, err := http.NewRequest("GET", baseURL+"/api/v2/torrents/info", nil)
	if err != nil {
		return TorrentSummary{}, err
	}

	resp, err := client.Do(req)
	if err != nil {
		return TorrentSummary{}, err
	}
	defer resp.Body.Close()

	debugLog("fetchTorrentsOnce status: %s", resp.Status)

	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return TorrentSummary{}, errUnauthorized
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		debugLog("Non-OK response body: %s", string(body))
		return TorrentSummary{}, fmt.Errorf("failed to fetch torrents, status: %s", resp.Status)
	}

	var fullTorrents []map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&fullTorrents); err != nil {
		return TorrentSummary{}, err
	}

	return summarizeTorrents(fullTorrents), nil
}

func summarizeTorrents(fullTorrents []map[string]interface{}) TorrentSummary {
	torrents := make([]TorrentInfo, 0, len(fullTorrents))
	var totalSpeed float64
	seeding := 0
	leeching := 0

	for _, t := range fullTorrents {
		ti := TorrentInfo{
			Name:       toString(t["name"]),
			Category:   toString(t["category"]),
			NumLeechs:  toInt(t["num_leechs"]),
			NumSeeds:   toInt(t["num_seeds"]),
			Progress:   toFloat(t["progress"]),
			State:      toString(t["state"]),
			Size:       toInt64(t["size"]),
			Downloaded: toInt64(t["downloaded"]),
			ETA:        toInt64(t["eta"]),
		}

		torrents = append(torrents, ti)

		if s, ok := t["dlspeed"].(float64); ok {
			totalSpeed += s
		}

		switch ti.State {
		case "uploading", "forcedUP", "stoppedUP":
			seeding++
		case "downloading", "forcedDL":
			leeching++
		}
	}

	return TorrentSummary{
		TotalDownloadSpeed: totalSpeed,
		SeedingCount:       seeding,
		LeechingCount:      leeching,
		Torrents:           torrents,
	}
}

func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		debugLog("Received Authorization token: %s", token)

		if token != authToken {
			debugLog("Authorization failed")
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

func rateLimitMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !checkRateLimit() {
			rateLimitMutex.Lock()
			remainingTime := time.Until(rateLimitWindow)
			rateLimitMutex.Unlock()

			w.Header().Set("X-RateLimit-Limit", strconv.Itoa(rateLimitPerMinute))
			w.Header().Set("X-RateLimit-Remaining", "0")
			w.Header().Set("X-RateLimit-Reset", strconv.FormatInt(rateLimitWindow.Unix(), 10))
			w.Header().Set("Retry-After", strconv.FormatInt(int64(remainingTime.Seconds()), 10))

			http.Error(w, fmt.Sprintf("Rate limit exceeded. Try again in %v seconds", int64(remainingTime.Seconds())), http.StatusTooManyRequests)
			return
		}
		next(w, r)
	}
}

func torrentsHandler(w http.ResponseWriter, r *http.Request) {
	now := time.Now()
	cacheMutex.RLock()
	if now.Before(cacheExpiry) && cache.Torrents != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(cache)
		cacheMutex.RUnlock()
		return
	}
	cacheMutex.RUnlock()

	cacheMutex.Lock()
	defer cacheMutex.Unlock()

	torrents, err := fetchTorrents()
	if err != nil {
		http.Error(w, "Failed to fetch torrents: "+err.Error(), http.StatusBadGateway)
		return
	}

	cache = torrents
	if cacheDurationMinutes > 0 {
		cacheExpiry = now.Add(time.Duration(cacheDurationMinutes) * time.Minute)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(cache)
}

// Helper conversion functions
func toString(v interface{}) string {
	if v == nil {
		return ""
	}
	return fmt.Sprintf("%v", v)
}

func toInt(v interface{}) int {
	switch val := v.(type) {
	case float64:
		return int(val)
	case int:
		return val
	case string:
		i, _ := strconv.Atoi(val)
		return i
	default:
		return 0
	}
}

func toInt64(v interface{}) int64 {
	switch val := v.(type) {
	case float64:
		return int64(val)
	case int:
		return int64(val)
	case int64:
		return val
	case string:
		i, _ := strconv.ParseInt(val, 10, 64)
		return i
	default:
		return 0
	}
}

func toFloat(v interface{}) float64 {
	switch val := v.(type) {
	case float64:
		return val
	case int:
		return float64(val)
	case string:
		f, _ := strconv.ParseFloat(val, 64)
		return f
	default:
		return 0
	}
}

func main() {
	baseURL = os.Getenv("QBIT_URL")
	username = os.Getenv("QBIT_USERNAME")
	password = os.Getenv("QBIT_PASSWORD")
	authToken = os.Getenv("API_TOKEN")
	debug = os.Getenv("DEBUG") == "1"

	if cd := os.Getenv("CACHE_DURATION"); cd != "" {
		if d, err := strconv.Atoi(cd); err == nil {
			cacheDurationMinutes = d
		} else {
			cacheDurationMinutes = 1
		}
	} else {
		cacheDurationMinutes = 1
	}

	if err := login(); err != nil {
		log.Fatalf("Initial login failed: %v", err)
	}

	initRateLimit()

	http.HandleFunc("/torrents", authMiddleware(rateLimitMiddleware(torrentsHandler)))

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	log.Printf("Server starting on port %s", port)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}
