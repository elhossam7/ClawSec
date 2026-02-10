# Build stage
FROM golang:1.22-alpine AS builder

RUN apk add --no-cache gcc musl-dev sqlite-dev

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=1 GOOS=linux go build -ldflags "-s -w -X main.Version=docker -X main.BuildTime=$(date -u +%Y-%m-%dT%H:%M:%SZ)" -o /sentinel ./cmd/sentinel/

# Runtime stage
FROM alpine:3.19

RUN apk add --no-cache ca-certificates sqlite iptables

# Non-root user
RUN addgroup -S sentinel && adduser -S sentinel -G sentinel

WORKDIR /opt/sentinel
COPY --from=builder /sentinel /usr/local/bin/sentinel
COPY rules/ ./rules/
COPY web/ ./web/

RUN mkdir -p data && chown -R sentinel:sentinel /opt/sentinel

USER sentinel

EXPOSE 8080

VOLUME ["/opt/sentinel/data"]

ENTRYPOINT ["sentinel"]
CMD ["run"]
