# featureforge service image (prototype). Mirrors the multi-stage pattern used
# by other vecta-kms services.
FROM golang:1.26.4 AS build
WORKDIR /src
COPY . .
RUN CGO_ENABLED=0 go build -o /out/featureforge ./cmd/featureforge

FROM gcr.io/distroless/static-debian12
COPY --from=build /out/featureforge /featureforge
EXPOSE 8099
ENTRYPOINT ["/featureforge"]
