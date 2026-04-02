# Build stage
FROM rust:latest AS builder

WORKDIR /app
COPY . .

RUN cargo build --release

# Runtime stage
FROM debian:sid

WORKDIR /app

RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/iota .

EXPOSE 1984

CMD ["./iota"]