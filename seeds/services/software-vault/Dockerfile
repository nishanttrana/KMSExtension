FROM vecta-local/golang:1.27.1-alpine AS build
# Link the CMVP-certified Go Cryptographic Module (docs/SECURITY/FIPS.md).
# The customer picks the runtime mode with VECTA_FIPS_MODE (on | only | off).
ENV GOFIPS140=v1.0.0
ARG TARGETOS
ARG TARGETARCH
WORKDIR /src
ENV GOPROXY=https://proxy.golang.org,direct \
    GOSUMDB=sum.golang.org \
    GOFLAGS=-mod=mod
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod sh -ec 'for attempt in 1 2 3 4 5; do go mod download && exit 0; sleep $((attempt * 2)); done; exit 1'
COPY . .
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH} go build -o /out/kms-software-vault ./services/software-vault

FROM vecta-local/alpine:3.24
RUN adduser -D -u 10001 app
WORKDIR /app
COPY --from=build /out/kms-software-vault /app/kms-software-vault
USER app
EXPOSE 8440 18440
ENTRYPOINT ["/app/kms-software-vault"]
