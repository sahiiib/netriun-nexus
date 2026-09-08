FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /nexus ./cmd/nexus

FROM alpine:3.23
RUN apk add --no-cache ca-certificates && addgroup -S nexus && adduser -S -G nexus nexus
COPY --from=build /nexus /usr/local/bin/nexus
USER nexus
EXPOSE 8080
ENTRYPOINT ["nexus"]
