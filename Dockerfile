FROM rust:1@sha256:f5375f865a8a5a734b9b9a38d58cd322d6a2eb8bb1aea8def32b89837258e7f8 AS chef

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

FROM debian:bookworm-slim@sha256:1537a6a1cbc4b4fd401da800ee9480207e7dc1f23560c21259f681db56768f63 AS runtime

LABEL org.opencontainers.image.source="https://github.com/twosmallonions/bff"
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
