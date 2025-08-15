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
	"strconv"
	"strings"
	"sync"
	"time"
	"path/filepath"
)

var (
	client           *http.Client
	baseURL          string
	username         string
	password         string
	authToken        string
	debug            bool
	cache            []TorrentInfo
	cacheMutex       sync.RWMutex
	cacheExpiry      time.Time
	loginAttempts    int
	loginBlockedUntil time.Time
	loginMutex       sync.Mutex
	rateLimitRequests  int
	rateLimitMutex     sync.Mutex
	rateLimitWindow    time.Time
	rateLimitPerMinute int
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
	Ratio      float64 `json:"ratio"`
	Priority   int     `json:"priority"`
	UploadedSession int64 `json:"uploaded_session"`
	DownloadedSession int64 `json:"downloaded_session"`
	Dlspeed    int64   `json:"dlspeed"`
	Upspeed    int64   `json:"upspeed"`
}

func debugLog(format string, args ...interface{}) {
	if debug {
		log.Printf("[DEBUG] "+format, args...)
	}
}

func initRateLimit() {
	rateLimitStr := os.Getenv("RATE_LIMIT")
	if rateLimitStr == "" {
		rateLimitPerMinute = 10 // Default rate limit
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

func fetchTorrents() ([]TorrentInfo, error) {
	torrents, err := fetchTorrentsOnce()
	if err == errUnauthorized {
		log.Println("Session expired, re-logging in...")
		if err = login(); err != nil {
			return nil, err
		}
		torrents, err = fetchTorrentsOnce()
	}
	return torrents, err
}

var errUnauthorized = fmt.Errorf("unauthorized")

func fetchTorrentsOnce() ([]TorrentInfo, error) {
	req, err := http.NewRequest("GET", baseURL+"/api/v2/torrents/info", nil)
	if err != nil {
		return nil, err
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	debugLog("fetchTorrentsOnce status: %s", resp.Status)

	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return nil, errUnauthorized
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		debugLog("Non-OK response body: %s", string(body))
		return nil, fmt.Errorf("failed to fetch torrents, status: %s", resp.Status)
	}

	var fullTorrents []map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&fullTorrents); err != nil {
		return nil, err
	}

	return parseTorrents(fullTorrents), nil
}

func parseTorrents(fullTorrents []map[string]interface{}) []TorrentInfo {
	filtered := make([]TorrentInfo, 0, len(fullTorrents))
	for _, t := range fullTorrents {
		filtered = append(filtered, TorrentInfo{
			Name:       toString(t["name"]),
			Category:   toString(t["category"]),
			NumLeechs:  toInt(t["num_leechs"]),
			NumSeeds:   toInt(t["num_seeds"]),
			Progress:   toFloat(t["progress"]),
			State:      toString(t["state"]),
			Size:       toInt64(t["size"]),
			Downloaded: toInt64(t["downloaded"]),
			ETA:        toInt64(t["eta"]),
			Ratio:      toFloat(t["ratio"]),
			Priority:   toInt(t["priority"]),
			UploadedSession: toInt64(t["uploaded_session"]),
			DownloadedSession: toInt64(t["downloaded_session"]),
			Dlspeed:    toInt64(t["dlspeed"]),
			Upspeed:    toInt64(t["upspeed"]),
		})
	}
	return filtered
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
			
			http.Error(w, fmt.Sprintf("Rate limit exceeded. Try again in %v", remainingTime.Round(time.Second)), http.StatusTooManyRequests)
			return
		}
		rateLimitMutex.Lock()
		remaining := rateLimitPerMinute - rateLimitRequests
		if remaining < 0 {
			remaining = 0
		}
		rateLimitMutex.Unlock()
		
		w.Header().Set("X-RateLimit-Limit", strconv.Itoa(rateLimitPerMinute))
		w.Header().Set("X-RateLimit-Remaining", strconv.Itoa(remaining))
		w.Header().Set("X-RateLimit-Reset", strconv.FormatInt(rateLimitWindow.Unix(), 10))
		
		next(w, r)
	}
}

func metricsHandler(w http.ResponseWriter, r *http.Request) {
	now := time.Now()
	
	cacheMutex.RLock()
	if now.Before(cacheExpiry) && cache != nil {
		debugLog("Serving metrics from cache (expires at %v, %v remaining)", 
			cacheExpiry.Format("15:04:05"), 
			time.Until(cacheExpiry).Round(time.Second))
		writeMetrics(w, cache)
		cacheMutex.RUnlock()
		return
	}
	cacheMutex.RUnlock()

	cacheMutex.Lock()
	defer cacheMutex.Unlock()

	if cacheDurationMinutes > 0 && now.Before(cacheExpiry) && cache != nil {
		debugLog("Serving metrics from cache (double-check, expires at %v, %v remaining)", 
			cacheExpiry.Format("15:04:05"), 
			time.Until(cacheExpiry).Round(time.Second))
		writeMetrics(w, cache)
		return
	}

	if cache == nil {
		debugLog("Cache is empty, fetching fresh data from qBittorrent API")
	} else {
		debugLog("Cache expired at %v, fetching fresh data from qBittorrent API", cacheExpiry.Format("15:04:05"))
	}

	torrents, err := fetchTorrents()
	if err != nil {
		debugLog("Failed to fetch torrents from API: %v", err)
		http.Error(w, "Failed to fetch torrents: "+err.Error(), http.StatusBadGateway)
		return
	}

	cache = torrents
	if cacheDurationMinutes > 0 {
		cacheExpiry = time.Now().Add(time.Duration(cacheDurationMinutes) * time.Minute)
	} else {
		cacheExpiry = time.Time{}
	}
	
	debugLog("Successfully fetched %d torrents from API, cached until %v", 
		len(torrents), 
		cacheExpiry.Format("15:04:05"))

	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	writeMetrics(w, cache)
}

func writeMetrics(w http.ResponseWriter, torrents []TorrentInfo) {
	// Helper function to sanitize label values
	sanitize := func(s string) string {
		s = strings.ReplaceAll(s, `\`, `\\`)
		s = strings.ReplaceAll(s, `"`, `\"`)
		s = strings.ReplaceAll(s, "\n", `\n`)
		s = strings.ReplaceAll(s, "\r", `\r`)
		s = strings.ReplaceAll(s, "\t", `\t`)
		return s
	}

	// Write metric headers
	fmt.Fprintln(w, "# HELP qbittorrent_torrent_info Information about torrents")
	fmt.Fprintln(w, "# TYPE qbittorrent_torrent_info gauge")
	
	fmt.Fprintln(w, "# HELP qbittorrent_torrent_size_bytes Size of torrent in bytes")
	fmt.Fprintln(w, "# TYPE qbittorrent_torrent_size_bytes gauge")
	
	fmt.Fprintln(w, "# HELP qbittorrent_torrent_downloaded_bytes Downloaded bytes")
	fmt.Fprintln(w, "# TYPE qbittorrent_torrent_downloaded_bytes gauge")
	
	fmt.Fprintln(w, "# HELP qbittorrent_torrent_progress Progress ratio (0-1)")
	fmt.Fprintln(w, "# TYPE qbittorrent_torrent_progress gauge")
	
	fmt.Fprintln(w, "# HELP qbittorrent_torrent_seeds Number of seeds")
	fmt.Fprintln(w, "# TYPE qbittorrent_torrent_seeds gauge")
	
	fmt.Fprintln(w, "# HELP qbittorrent_torrent_leeches Number of leeches")
	fmt.Fprintln(w, "# TYPE qbittorrent_torrent_leeches gauge")
	
	fmt.Fprintln(w, "# HELP qbittorrent_torrent_ratio Share ratio")
	fmt.Fprintln(w, "# TYPE qbittorrent_torrent_ratio gauge")
	
	fmt.Fprintln(w, "# HELP qbittorrent_torrent_eta_seconds Estimated time to completion in seconds")
	fmt.Fprintln(w, "# TYPE qbittorrent_torrent_eta_seconds gauge")
	
	fmt.Fprintln(w, "# HELP qbittorrent_torrent_download_speed_bytes_per_second Current download speed")
	fmt.Fprintln(w, "# TYPE qbittorrent_torrent_download_speed_bytes_per_second gauge")
	
	fmt.Fprintln(w, "# HELP qbittorrent_torrent_upload_speed_bytes_per_second Current upload speed")
	fmt.Fprintln(w, "# TYPE qbittorrent_torrent_upload_speed_bytes_per_second gauge")
	
	fmt.Fprintln(w, "# HELP qbittorrent_torrent_uploaded_session_bytes Uploaded bytes this session")
	fmt.Fprintln(w, "# TYPE qbittorrent_torrent_uploaded_session_bytes gauge")
	
	fmt.Fprintln(w, "# HELP qbittorrent_torrent_downloaded_session_bytes Downloaded bytes this session")
	fmt.Fprintln(w, "# TYPE qbittorrent_torrent_downloaded_session_bytes gauge")

	// Aggregate metrics
	var (
		totalTorrents      = len(torrents)
		totalSize         int64
		totalDownloaded   int64
		totalSeeds        int
		totalLeeches      int
		totalDownloadSpeed int64
		totalUploadSpeed  int64
		stateCount        = make(map[string]int)
		categoryCount     = make(map[string]int)
	)

	// Write per-torrent metrics and collect aggregate data
	for _, torrent := range torrents {
		labels := fmt.Sprintf(`name="%s",category="%s",state="%s"`, 
			sanitize(torrent.Name), 
			sanitize(torrent.Category), 
			sanitize(torrent.State))

		fmt.Fprintf(w, "qbittorrent_torrent_info{%s} 1\n", labels)
		fmt.Fprintf(w, "qbittorrent_torrent_size_bytes{%s} %d\n", labels, torrent.Size)
		fmt.Fprintf(w, "qbittorrent_torrent_downloaded_bytes{%s} %d\n", labels, torrent.Downloaded)
		fmt.Fprintf(w, "qbittorrent_torrent_progress{%s} %.6f\n", labels, torrent.Progress)
		fmt.Fprintf(w, "qbittorrent_torrent_seeds{%s} %d\n", labels, torrent.NumSeeds)
		fmt.Fprintf(w, "qbittorrent_torrent_leeches{%s} %d\n", labels, torrent.NumLeechs)
		fmt.Fprintf(w, "qbittorrent_torrent_ratio{%s} %.6f\n", labels, torrent.Ratio)
		fmt.Fprintf(w, "qbittorrent_torrent_eta_seconds{%s} %d\n", labels, torrent.ETA)
		fmt.Fprintf(w, "qbittorrent_torrent_download_speed_bytes_per_second{%s} %d\n", labels, torrent.Dlspeed)
		fmt.Fprintf(w, "qbittorrent_torrent_upload_speed_bytes_per_second{%s} %d\n", labels, torrent.Upspeed)
		fmt.Fprintf(w, "qbittorrent_torrent_uploaded_session_bytes{%s} %d\n", labels, torrent.UploadedSession)
		fmt.Fprintf(w, "qbittorrent_torrent_downloaded_session_bytes{%s} %d\n", labels, torrent.DownloadedSession)

		// Aggregate data
		totalSize += torrent.Size
		totalDownloaded += torrent.Downloaded
		totalSeeds += torrent.NumSeeds
		totalLeeches += torrent.NumLeechs
		totalDownloadSpeed += torrent.Dlspeed
		totalUploadSpeed += torrent.Upspeed
		stateCount[torrent.State]++
		categoryCount[torrent.Category]++
	}

	// Write aggregate metrics
	fmt.Fprintln(w, "# HELP qbittorrent_total_torrents Total number of torrents")
	fmt.Fprintln(w, "# TYPE qbittorrent_total_torrents gauge")
	fmt.Fprintf(w, "qbittorrent_total_torrents %d\n", totalTorrents)

	fmt.Fprintln(w, "# HELP qbittorrent_total_size_bytes Total size of all torrents")
	fmt.Fprintln(w, "# TYPE qbittorrent_total_size_bytes gauge")
	fmt.Fprintf(w, "qbittorrent_total_size_bytes %d\n", totalSize)

	fmt.Fprintln(w, "# HELP qbittorrent_total_downloaded_bytes Total downloaded bytes")
	fmt.Fprintln(w, "# TYPE qbittorrent_total_downloaded_bytes gauge")
	fmt.Fprintf(w, "qbittorrent_total_downloaded_bytes %d\n", totalDownloaded)

	fmt.Fprintln(w, "# HELP qbittorrent_total_seeds Total number of seeds")
	fmt.Fprintln(w, "# TYPE qbittorrent_total_seeds gauge")
	fmt.Fprintf(w, "qbittorrent_total_seeds %d\n", totalSeeds)

	fmt.Fprintln(w, "# HELP qbittorrent_total_leeches Total number of leeches")
	fmt.Fprintln(w, "# TYPE qbittorrent_total_leeches gauge")
	fmt.Fprintf(w, "qbittorrent_total_leeches %d\n", totalLeeches)

	fmt.Fprintln(w, "# HELP qbittorrent_total_download_speed_bytes_per_second Total download speed")
	fmt.Fprintln(w, "# TYPE qbittorrent_total_download_speed_bytes_per_second gauge")
	fmt.Fprintf(w, "qbittorrent_total_download_speed_bytes_per_second %d\n", totalDownloadSpeed)

	fmt.Fprintln(w, "# HELP qbittorrent_total_upload_speed_bytes_per_second Total upload speed")
	fmt.Fprintln(w, "# TYPE qbittorrent_total_upload_speed_bytes_per_second gauge")
	fmt.Fprintf(w, "qbittorrent_total_upload_speed_bytes_per_second %d\n", totalUploadSpeed)

	// State distribution metrics
	fmt.Fprintln(w, "# HELP qbittorrent_torrents_by_state Number of torrents by state")
	fmt.Fprintln(w, "# TYPE qbittorrent_torrents_by_state gauge")
	for state, count := range stateCount {
		fmt.Fprintf(w, "qbittorrent_torrents_by_state{state=\"%s\"} %d\n", sanitize(state), count)
	}

	// Category distribution metrics
	fmt.Fprintln(w, "# HELP qbittorrent_torrents_by_category Number of torrents by category")
	fmt.Fprintln(w, "# TYPE qbittorrent_torrents_by_category gauge")
	for category, count := range categoryCount {
		fmt.Fprintf(w, "qbittorrent_torrents_by_category{category=\"%s\"} %d\n", sanitize(category), count)
	}

	// Exporter metadata
	fmt.Fprintln(w, "# HELP qbittorrent_exporter_up Whether the exporter is up")
	fmt.Fprintln(w, "# TYPE qbittorrent_exporter_up gauge")
	fmt.Fprintln(w, "qbittorrent_exporter_up 1")

	fmt.Fprintln(w, "# HELP qbittorrent_exporter_last_scrape_timestamp_seconds Last scrape timestamp")
	fmt.Fprintln(w, "# TYPE qbittorrent_exporter_last_scrape_timestamp_seconds gauge")
	fmt.Fprintf(w, "qbittorrent_exporter_last_scrape_timestamp_seconds %d\n", time.Now().Unix())
}

func toString(i interface{}) string {
	if s, ok := i.(string); ok {
		return s
	}
	return ""
}

func toInt(i interface{}) int {
	switch v := i.(type) {
	case float64:
		return int(v)
	case int:
		return v
	default:
		return 0
	}
}

func toInt64(i interface{}) int64 {
	switch v := i.(type) {
	case float64:
		return int64(v)
	case int64:
		return v
	case int:
		return int64(v)
	default:
		return 0
	}
}

func toFloat(i interface{}) float64 {
	if f, ok := i.(float64); ok {
		return f
	}
	return 0
}

func cleanOldLogs(logDir string, retentionDays int) {
	if retentionDays == 0 {
		log.Println("LOG_RETENTION_DAYS=0; purging all logs")
	} else {
		log.Printf("Cleaning logs older than %d days in %s\n", retentionDays, logDir)
	}

	now := time.Now()
	_ = filepath.Walk(logDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}

		if !strings.HasSuffix(info.Name(), ".log") {
			return nil
		}

		age := now.Sub(info.ModTime())
		if retentionDays == 0 || age > (time.Duration(retentionDays)*24*time.Hour) {
			log.Printf("Removing old log: %s (age: %v)", path, age.Round(time.Second))
			os.Remove(path)
		}
		return nil
	})
}

func main() {        
	baseURL = strings.TrimRight(os.Getenv("BASE_URL"), "/")
	username = os.Getenv("USERNAME")
	password = os.Getenv("PASSWORD")
	authToken = os.Getenv("AUTH_TOKEN")
	debug = os.Getenv("DEBUG") == "true"

	logDir := os.Getenv("LOG_DIR")
	if logDir == "" {
		logDir = "./logs"
	}
	if err := os.MkdirAll(logDir, 0755); err != nil {
		fmt.Printf("Failed to create log directory: %v\n", err)
		os.Exit(1)
	}

	logFileName := filepath.Join(logDir, "app-"+time.Now().Format("2006-01-02_15-04-05")+".log")
	logFile, err := os.OpenFile(logFileName, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		fmt.Printf("Failed to open log file: %v\n", err)
		os.Exit(1)
	}

	cacheDurationMinutes = 5
	if val := os.Getenv("CACHE_DURATION"); val != "" {
		if parsed, err := strconv.Atoi(val); err == nil && parsed >= 0 {
			cacheDurationMinutes = parsed
			log.Printf("CACHE_DURATION set to %d minute(s)", cacheDurationMinutes)
		} else {
			log.Printf("Invalid CACHE_DURATION: %s, using default of 5 minutes", val)
		}
	}

	log.SetOutput(io.MultiWriter(os.Stdout, logFile))

	if baseURL == "" || username == "" || password == "" || authToken == "" {
		log.Fatal("Missing required environment variables")
	}

	retention := 3
	if val := os.Getenv("LOG_RETENTION_DAYS"); val != "" {
		if parsed, err := strconv.Atoi(val); err == nil && parsed >= 0 {
			retention = parsed
		} else {
			log.Printf("Invalid LOG_RETENTION_DAYS: %s, defaulting to %d", val, retention)
		}
	}

	cleanOldLogs(logDir, retention)
	initRateLimit()

	if err := login(); err != nil {
		log.Fatalf("Initial login failed: %v", err)
	}

	port := os.Getenv("LISTEN_PORT")
	if port == "" {
		port = "9911"
	}

	// Set up the metrics endpoint
	http.HandleFunc("/metrics", authMiddleware(rateLimitMiddleware(metricsHandler)))
	
	// Optional: Add a health check endpoint
	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})
	
	log.Printf("qBittorrent Prometheus Exporter listening on :%s\n", port)
	log.Printf("Metrics available at http://localhost:%s/metrics\n", port)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}
