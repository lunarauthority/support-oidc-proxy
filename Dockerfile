# syntax=docker/dockerfile:1
#
# Two-stage build for support-oidc-proxy.
# Stage 1: compile the Go binary.
# Stage 2: distroless static runtime — no shell, no package manager.

FROM golang:1.26-bookworm AS builder

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags="-s -w" \
    -o /support-oidc-proxy \
    ./cmd/support-oidc-proxy

FROM gcr.io/distroless/static-debian12:nonroot AS runtime

COPY --from=builder /support-oidc-proxy /support-oidc-proxy

EXPOSE 8080
ENTRYPOINT ["/support-oidc-proxy"]
