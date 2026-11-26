FROM golang:alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY *.go ./
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /tunnel . \
 && mkdir -p /data

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /tunnel /tunnel
# /data holds the self-signed cert so its fingerprint survives restarts
COPY --from=build --chown=nonroot:nonroot /data /data
VOLUME /data
EXPOSE 8443
ENTRYPOINT ["/tunnel", "server", "-listen", ":8443", "-selfsigned", "/data/tunnel-selfsigned"]
