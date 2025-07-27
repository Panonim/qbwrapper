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

func torrentsHandler(w http.ResponseWriter, r *http.Request) {
        now := time.Now()
        
        cacheMutex.RLock()
        if now.Before(cacheExpiry) && cache != nil {
                debugLog("Serving torrents from cache (expires at %v, %v remaining)", 
                        cacheExpiry.Format("15:04:05"), 
                        time.Until(cacheExpiry).Round(time.Second))
                json.NewEncoder(w).Encode(cache)
                cacheMutex.RUnlock()
                return
        }
        cacheMutex.RUnlock()

        cacheMutex.Lock()
        defer cacheMutex.Unlock()

        if now.Before(cacheExpiry) && cache != nil {
                debugLog("Serving torrents from cache (double-check, expires at %v, %v remaining)", 
                        cacheExpiry.Format("15:04:05"), 
                        time.Until(cacheExpiry).Round(time.Second))
                json.NewEncoder(w).Encode(cache)
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
        cacheExpiry = time.Now().Add(5 * time.Minute)
        
        debugLog("Successfully fetched %d torrents from API, cached until %v", 
                len(torrents), 
                cacheExpiry.Format("15:04:05"))

        w.Header().Set("Content-Type", "application/json")
        json.NewEncoder(w).Encode(cache)
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

        http.HandleFunc("/qb/torrents", authMiddleware(rateLimitMiddleware(torrentsHandler)))
        log.Printf("Listening on :%s\n", port)
        log.Fatal(http.ListenAndServe(":"+port, nil))
}
