FROM golang:1.27.0-alpine AS build

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /out/bearly-secure ./cmd/server
RUN CGO_ENABLED=0 go build -o /out/bearly-attacker-lab ./cmd/attackerlab

FROM alpine:3.22

RUN apk add --no-cache ca-certificates

WORKDIR /app

COPY --from=build /out/bearly-secure /out/bearly-attacker-lab ./
COPY attacker-lab ./attacker-lab
COPY web ./web
COPY data/fixtures ./data/fixtures

RUN addgroup -S bearly \
    && adduser -S -G bearly bearly \
    && chown bearly:bearly ./data

USER bearly

EXPOSE 3030 4040
CMD ["./bearly-secure"]
