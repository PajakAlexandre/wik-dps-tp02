# Use Debian as the base image
FROM debian:buster-slim

# Set the working directory
WORKDIR /app

# Create a non-root user
RUN useradd -ms /bin/bash rust_api_user

# Install necessary build tools for Rust
RUN apt-get update && apt-get install -y \
    curl \
    gcc \
    libc6-dev \
    make

# Copy your application source code and Cargo files
COPY src ./src/
COPY Cargo.toml Cargo.lock ./

# Build the Rust application
RUN curl https://sh.rustup.rs -sSf | sh -s -- -y && \
    /root/.cargo/bin/cargo build --release \
    && rm -rf /root/.cargo \
    && rm -rf /root/.rustup \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get purge -y --auto-remove curl gcc libc6-dev make \
    && apt-get clean

# Change ownership of the application directory to the new user
RUN chown -R rust_api_user:rust_api_user /app

# Switch to the new user
USER rust_api_user

# Start the Actix Web application
CMD ["/app/target/release/rust_api"]
