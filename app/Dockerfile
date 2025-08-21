# Builder
FROM golang:1.21-bullseye AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod tidy
COPY . .
RUN go build -o app ./...

# Final
FROM debian:bullseye-slim
WORKDIR /app
COPY --from=builder /app/app .
EXPOSE 9911
CMD ["./app"]
