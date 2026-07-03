# hive-relay — build from this repo root: docker build -t hive-relay .
FROM golang:1.25-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/hive-relay ./cmd/hive-relay

FROM alpine:3.20
RUN apk add --no-cache su-exec && adduser -D -H hive
COPY --from=build /out/hive-relay /usr/local/bin/hive-relay
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh
ENV HIVE_RELAY_ADDR=0.0.0.0:8443
# In-memory + snapshot store here; set DATABASE_URL for a shared Postgres store
# (horizontal scaling / HA, no data migration) — it takes precedence.
ENV HIVE_RELAY_DATA_DIR=/data
EXPOSE 8443
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
