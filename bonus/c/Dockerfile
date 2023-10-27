# Build stage
FROM busybox:glibc
# Set the working directory
WORKDIR /app
# Copy the built binary
COPY counter /app/counter
# Start the application
CMD ["/app/counter"]

