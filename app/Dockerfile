# ---------- Builder Stage ----------
FROM golang:1.21-alpine AS builder

WORKDIR /app
RUN apk --no-cache add git bash

COPY go.mod go.sum ./
RUN go mod tidy

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -o app ./...

# ---------- Final Stage ----------
FROM alpine:latest

WORKDIR /app
RUN apk --no-cache add tzdata
COPY --from=builder /app/app .

EXPOSE 9911
CMD ["./app"]
