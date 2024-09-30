FROM rust:1 AS chef

RUN cargo install cargo-chef
WORKDIR /app

FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder

COPY --from=planner /app/recipe.json recipe.json

RUN cargo chef cook --release --recipe-path recipe.json

COPY . .
RUN cargo build --release --bin bff

FROM debian:bookworm-slim AS runtime

LABEL org.opencontainers.image.source="https://github.com/Two-Small-Onions/bff"
LABEL org.opencontainers.image.description="TSO bff"
LABEL org.opencontainers.image.licenses=MIT

RUN apt-get update && apt-get install -y \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN useradd -ms /bin/bash bffuser

EXPOSE 8082

WORKDIR /app
COPY --from=builder /app/target/release/bff /app/bff
USER bffuser
ENTRYPOINT [ "/app/bff" ]
