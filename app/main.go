package main

import (
        "encoding/json"
        "io"
        "log"
        "net/http"
        "net/http/cookiejar"
        "net/url"
        "os"
        "strings"
        "sync"
        "time"

        "github.com/joho/godotenv"
)

var (
        client      *http.Client
        qbBaseURL   string
        authToken   string
        cache       []TorrentInfo
        cacheMutex  sync.RWMutex
        cacheExpiry time.Time
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

func loginToQbittorrent(qbURL, username, password string) {
        jar, _ := cookiejar.New(nil)
        client = &http.Client{Jar: jar}

        form := url.Values{}
        form.Add("username", username)
        form.Add("password", password)

        loginURL := strings.TrimRight(qbURL, "/") + "/api/v2/auth/login"
        resp, err := client.PostForm(loginURL, form)
        if err != nil {
                log.Fatalf("Login failed: %v", err)
        }
        defer resp.Body.Close()

        body, _ := io.ReadAll(resp.Body)
        if string(body) != "Ok." {
                log.Fatalf("Login failed, response: %s", body)
        }

        log.Println("qBittorrent login successful")
}

func fetchTorrents() ([]TorrentInfo, error) {
        req, err := http.NewRequest("GET", qbBaseURL+"/api/v2/torrents/info", nil)
        if err != nil {
                return nil, err
        }

        resp, err := client.Do(req)
        if err != nil {
                return nil, err
        }
        defer resp.Body.Close()

        var fullTorrents []map[string]interface{}
        if err := json.NewDecoder(resp.Body).Decode(&fullTorrents); err != nil {
                return nil, err
        }

        var filtered []TorrentInfo
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

        return filtered, nil
}

func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
        return func(w http.ResponseWriter, r *http.Request) {
                token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
                if token != authToken {
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
                http.Error(w, "Failed to fetch torrents", http.StatusBadGateway)
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
        if err := godotenv.Load(); err != nil {
                log.Fatal("Error loading .env")
        }

        qbBaseURL = strings.TrimRight(os.Getenv("QB_URL"), "/")
        username := os.Getenv("QB_USERNAME")
        password := os.Getenv("QB_PASSWORD")
        authToken = os.Getenv("AUTH_TOKEN")

        if qbBaseURL == "" || username == "" || password == "" || authToken == "" {
                log.Fatal("Missing required .env variables")
        }

        loginToQbittorrent(qbBaseURL, username, password)

        port := os.Getenv("LISTEN_PORT")
        if port == "" {
                port = "9911"
        }

        http.HandleFunc("/qb/torrents", authMiddleware(torrentsHandler))
        log.Printf("Listening on :%s\n", port)
        log.Fatal(http.ListenAndServe(":"+port, nil))
}
