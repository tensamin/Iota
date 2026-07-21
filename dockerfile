# Build stage
FROM rust:latest AS builder

WORKDIR /app
COPY . .

RUN cargo build --release -p iota-daemon

# Runtime stage
FROM debian:sid

WORKDIR /app

RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/iota-daemon .

RUN useradd -r -s /bin/false iota && mkdir -p /run/iota && chown iota:iota /run/iota

EXPOSE 1984

CMD ["./iota-daemon"]
