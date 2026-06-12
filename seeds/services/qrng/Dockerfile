FROM vecta-local/golang:1.26.4-alpine AS build
WORKDIR /src
ENV GOPROXY=https://proxy.golang.org,direct \
    GOSUMDB=sum.golang.org \
    GOFLAGS=-mod=mod
COPY go.mod go.sum ./
RUN sh -ec 'for attempt in 1 2 3 4 5; do go mod download && exit 0; sleep $((attempt * 2)); done; exit 1'
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o /out/kms-qrng ./services/qrng

FROM vecta-local/alpine:3.23
RUN addgroup -S app && adduser -S app -G app
USER app
WORKDIR /app
COPY --from=build /out/kms-qrng /app/kms-qrng
COPY services/qrng/migrations /app/migrations
EXPOSE 8230 18230
ENTRYPOINT ["/app/kms-qrng"]
