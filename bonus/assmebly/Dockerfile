# Stage 1: Build the assembly program
FROM debian AS builder

# Install necessary tools
RUN apt-get update && apt-get install -y nasm gcc

# Set the working directory
WORKDIR /app

# Copy your assembly source file into the container
COPY number_printer.asm .

# Assemble and link the assembly program
RUN nasm -f elf64 -o number_printer.o number_printer.asm
RUN ld number_printer.o -o number_printer

# Stage 2: Create the final minimal image
FROM scratch

# Copy only the binary from the builder stage
COPY --from=builder /app/number_printer /

# Set the command to run when the container starts
CMD ["/number_printer"]
