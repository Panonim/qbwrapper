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
        "strings"
        "sync"
        "time"
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

func torrentsHandler(w http.ResponseWriter, r *http.Request) {
        cacheMutex.RLock()
        if time.Now().Before(cacheExpiry) && cache != nil {
                json.NewEncoder(w).Encode(cache)
                cacheMutex.RUnlock()
                return
        }
        cacheMutex.RUnlock()

        cacheMutex.Lock()
        defer cacheMutex.Unlock()

        if time.Now().Before(cacheExpiry) && cache != nil {
                json.NewEncoder(w).Encode(cache)
                return
        }

        torrents, err := fetchTorrents()
        if err != nil {
                http.Error(w, "Failed to fetch torrents: "+err.Error(), http.StatusBadGateway)
                return
        }

        cache = torrents
        cacheExpiry = time.Now().Add(5 * time.Minute)

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

func main() {
        baseURL = strings.TrimRight(os.Getenv("BASE_URL"), "/")
        username = os.Getenv("USERNAME")
        password = os.Getenv("PASSWORD")
        authToken = os.Getenv("AUTH_TOKEN")
        debug = os.Getenv("DEBUG") == "true"

        if baseURL == "" || username == "" || password == "" || authToken == "" {
                log.Fatal("Missing required environment variables")
        }

        if err := login(); err != nil {
                log.Fatalf("Initial login failed: %v", err)
        }

        port := os.Getenv("LISTEN_PORT")
        if port == "" {
                port = "9911"
        }

        http.HandleFunc("/qb/torrents", authMiddleware(torrentsHandler))
        log.Printf("Listening on :%s\n", port)
        log.Fatal(http.ListenAndServe(":"+port, nil))
}
