FROM golang:1.26.4-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG TARGETARCH=amd64
RUN CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH} go build -trimpath -ldflags="-s -w" -o /out/kms-tfe ./services/tfe

FROM alpine:3.23
RUN apk add --no-cache ca-certificates tzdata
RUN addgroup -S app && adduser -S app -G app
USER app
WORKDIR /app
COPY --from=build /out/kms-tfe /app/kms-tfe
EXPOSE 8450 18450
ENTRYPOINT ["/app/kms-tfe"]
