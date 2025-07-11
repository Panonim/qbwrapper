# Build stage
FROM golang:1.21-alpine AS builder

WORKDIR /app

RUN apk --no-cache add git

COPY . /app

RUN go mod tidy
RUN go build -o app main.go

# Final stage
FROM alpine:latest

WORKDIR /app

COPY --from=builder /app/app .

EXPOSE 9911

CMD ["./app"]
