# Build stage
FROM golang:1.21-alpine AS builder

WORKDIR /app

RUN apk --no-cache add git

COPY . .
RUN go mod tidy
RUN CGO_ENABLED=0 GOOS=linux go build -o app main.go

# Final stage
FROM alpine:latest

WORKDIR /app
RUN apk --no-cache add tzdata

COPY --from=builder /app/app . 

EXPOSE 9911
CMD ["./app"]
