FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /nexus ./cmd/nexus

FROM alpine:3.23
ARG VERSION=dev
ARG REVISION=unknown
ARG SOURCE=https://github.com/sahiiib/netriun-nexus
RUN apk add --no-cache ca-certificates && addgroup -S nexus && adduser -S -G nexus nexus
COPY --from=build /nexus /usr/local/bin/nexus
USER nexus
EXPOSE 8080
LABEL org.opencontainers.image.title="Netriun Nexus" \
      org.opencontainers.image.description="Multi-cloud orchestration control plane" \
      org.opencontainers.image.version=$VERSION \
      org.opencontainers.image.revision=$REVISION \
      org.opencontainers.image.source=$SOURCE \
      org.opencontainers.image.licenses="UNLICENSED"
ENTRYPOINT ["nexus"]
