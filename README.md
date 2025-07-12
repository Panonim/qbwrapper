# qBittorrent API Proxy

This Go app acts as a lightweight proxy API for qBittorrent. It logs into your qBittorrent Web UI, fetches torrent info, caches it for 5 minutes, and exposes a simple authenticated HTTP endpoint to get torrent data in JSON format.

## Environment Variables

You **must** provide these in a `.env` file or your environment:

* `QB_URL` — base URL of your qBittorrent Web UI (e.g., `http://localhost:8080`)
* `QB_USERNAME` — your qBittorrent username
* `QB_PASSWORD` — your qBittorrent password
* `AUTH_TOKEN` — Bearer token required to access the `/qb/torrents` endpoint

## What you get in the response

Each torrent object includes:

* `name`: Torrent name
* `category`: Assigned category in qBittorrent
* `num_leechs`: Number of leechers
* `num_seeds`: Number of seeders
* `progress`: Download progress (0 to 1)
* `state`: Torrent state (e.g., downloading, paused)
* `size`: Total size in bytes
* `downloaded`: Bytes downloaded so far
* `eta`: Estimated time remaining in seconds

## Notes

* The cache is locked for concurrency safety.
* If the qBittorrent login fails, the app exits.
* If you hit the endpoint without a valid token, you get a 401 Unauthorized.
* The app uses standard Go HTTP server and `github.com/joho/godotenv` for env loading.
