FROM golang:1.23-bookworm AS build
WORKDIR /src
RUN apt-get update && apt-get install -y --no-install-recommends nmap iputils-ping traceroute && rm -rf /var/lib/apt/lists/*
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /penego .

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates nmap iputils-ping traceroute \
  && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=build /penego /app/penego
EXPOSE 8585
ENTRYPOINT ["/app/penego"]
