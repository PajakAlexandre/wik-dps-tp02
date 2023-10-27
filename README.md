# Dockerised Rust API
___
## Description

From the TP wik-dps-tp01 API, we will dockerise it. First Dockerfile must be a single stage build. Then we will use a
multi-stage build to reduce the size of the image. 
A dedicated user will be created to run the API. The API will be run with the `CMD` instruction.

## Build rust_api_signle_stage image

from ./rust_api directory
```bash
vim Dockerfile
```
add this content:
```bash
# Use Debian as the base image
FROM debian:buster-slim

# Set the working directory
WORKDIR /app

# Install necessary build tools for Rust
RUN apt-get update && apt-get install -y \
    curl \
    gcc \
    libc6-dev \
    make \
    && rm -rf /var/lib/apt/lists/*

# Create a non-root user
RUN useradd -ms /bin/bash rust_api_user

# Copy your application source code and Cargo files
COPY src/ ./src/
COPY Cargo.toml Cargo.lock ./

# Build the Rust application
RUN curl https://sh.rustup.rs -sSf | sh -s -- -y && \
    /root/.cargo/bin/cargo build --release \
    && rm -rf /root/.cargo \
    && rm -rf /root/.rustup

# Change ownership of the application directory to the new user
RUN chown -R rust_api_user:rust_api_user /app

# Switch to the new user
USER rust_api_user

# Start the Actix Web application
CMD ["/app/target/release/rust_api"]
```
build the image
```bash
docker build -t rust_api_single_stage:latest .
```

## Run Single Stage Image
```bash
docker run -e PING_LISTEN_PORT=8081 -p 8081:8081 rust_api_single_stage:latest
```
## Security scan

[security report](./files/security_report_single_stage.md)

## Build rust_api multi-stages image

from ./rust_api directory
```bash
vim Dockerfile
```
add this content:
```bash
# Use the Rust image as the base image
FROM rust:1.68 as builder

# Set the working directory
WORKDIR /app

# Copy the Cargo.toml and Cargo.lock files to leverage Docker layer caching
COPY rust_api/Cargo.toml Cargo.lock ./

# Build the dependencies
RUN mkdir -p src && echo 'fn main() {}' > src/main.rs
RUN cargo build --release

# Remove the dummy source file
RUN rm src/main.rs

# Copy the source code to the container
COPY rust_api/src ./src/

# Build the Rust application
RUN cargo build --release

# Create a new lightweight image
FROM debian:buster-slim as runtime

# Set the working directory
WORKDIR /app

# Create a non-root user
RUN useradd -ms /bin/bash rust_api_user

# Change ownership of the application directory to the new user
RUN chown -R rust_api_user:rust_api_user /app

# setup application permissions
RUN chmod -R 755 /app

# Switch to the new user
USER rust_api_user

# Copy the built binary from the builder image
COPY --from=builder /app/target/release/rust_api ./rust_api

# Start the Actix Web application
CMD ["./rust_api"]
```
build the image 

```bash
docker build -t rust_api:latest .
```

## run 

```bash
docker run -e PING_LISTEN_PORT=8080 -p 8080:8080 rust_api:latest
```


## security scan:

[security report](./files/security_report_multi_stages.md)

## Bonus: 

### Smallest image for dockerized a 0 to 10000 counter

### First try with C and gcc

```bash
vim counter.c
```

```c
#include <stdio.h>
int main() {
for (int i = 0; i <= 10000; i++) {
printf("%d\n", i);
}
return 0;
}
```

```bash
vim Dockerfile
```
```dockerfile
# Use a minimal base image  Alpine Linux
FROM alpine:latest

# Install the C compiler (GCC) and the standard C library headers
RUN apk --no-cache add gcc musl-dev

# Copy your C code into the image
COPY main.c /app/main.c

# Set the working directory
WORKDIR /app

# Compile the C code and create an executable
RUN gcc -o counter main.c

# Clean up any unnecessary files
RUN rm main.c

# Set the entry point for your program
CMD ["/app/counter"]
```

### Build the image

```bash
docker build -t c-counter .
```
### Run the container

```bash
docker run c-counter
```

### Result

```bash
docker images
```

```bash
  main S:4 U:3 ?:1  ~/Ynov/B3/DevOps/wik-dps-tp02/bonus                                                                                                                                                                                                                                                                                                                                                      14:48:40  lexit 
❯ docker image ls
REPOSITORY     TAG       IMAGE ID       CREATED        SIZE
c-counter        latest    db01fc4967d7   24 hours ago   155MB
```

```bash
  main S:4 U:3 ?:1  ~/Ynov/B3/DevOps/wik-dps-tp02/bonus/c                                                                                                                                                                                                                                                                                                                                                    15:06:49  lexit 
❯ docker history c-counter:latest 
IMAGE          CREATED        CREATED BY                                      SIZE      COMMENT
db01fc4967d7   24 hours ago   CMD ["/app/counter"]                            0B        buildkit.dockerfile.v0
<missing>      24 hours ago   RUN /bin/sh -c rm main.c # buildkit             0B        buildkit.dockerfile.v0
<missing>      24 hours ago   RUN /bin/sh -c gcc -o counter main.c # build…   18.2kB    buildkit.dockerfile.v0
<missing>      24 hours ago   WORKDIR /app                                    0B        buildkit.dockerfile.v0
<missing>      24 hours ago   COPY main.c /app/main.c # buildkit              120B      buildkit.dockerfile.v0
<missing>      24 hours ago   RUN /bin/sh -c apk --no-cache add gcc musl-d…   148MB     buildkit.dockerfile.v0
<missing>      4 weeks ago    /bin/sh -c #(nop)  CMD ["/bin/sh"]              0B        
<missing>      4 weeks ago    /bin/sh -c #(nop) ADD file:756183bba9c7f4593…   7.34MB 
```

### Second try c bin file and `busybox:glibc`

Prebuild `c` code with:

```bash
gcc -o counter main.c
```

create Dockerfile

```dockerfile
# Build stage
FROM busybox:glibc
# Set the working directory
WORKDIR /app
# Copy the built binary
COPY counter /app/counter
# Start the application
CMD ["/app/counter"]
```

### Build the image

```bash
docker build -t c-bin .
```

### Run the container

```bash
docker run c-bin
```

### Result

```bash
❯ docker history c-bin
IMAGE          CREATED         CREATED BY                                      SIZE      COMMENT
75839a743734   3 minutes ago   CMD ["/app/counter"]                            0B        buildkit.dockerfile.v0
<missing>      3 minutes ago   COPY counter /app/counter # buildkit            16kB      buildkit.dockerfile.v0
<missing>      3 minutes ago   WORKDIR /app                                    0B        buildkit.dockerfile.v0
<missing>      3 months ago    /bin/sh -c #(nop)  CMD ["sh"]                   0B        
<missing>      3 months ago    /bin/sh -c #(nop) ADD file:7e9002edaafd4e457…   4.26MB   
```

```bash
  main S:5 U:3 ?:2  ~/Ynov/B3/DevOps/wik-dps-tp02/bonus/c                                                                                                                                                                                                                                                                                                                                                    15:56:52  lexit 
❯ docker images
REPOSITORY                                                TAG                                                                          IMAGE ID       CREATED         SIZE
c-bin                                                     latest                                                                       75839a743734   7 minutes ago   4.28MB
```


### Third try with `assembly` and `nasm`

```bash
vim number_printer.asm
```

```assembly
section .data
    num_format db "%ld", 10, 0   ; Format string for printing numbers with a newline
    num_buffer db 20, 0          ; Buffer to store the number as a string (up to 20 characters)

section .text
global _start

_start:
    xor rsi, rsi                 ; Initialize loop counter to 0

print_loop:
    mov rax, rsi                 ; Move loop counter to rax
    lea rdi, [num_buffer]        ; Load the address of the number buffer
    call itoa                    ; Convert rax to a string

    ; Calculate the length of the string
    mov rax, rdi                 ; rdi contains the address of the string
    call strlen

    ; Write the string to stdout
    mov rax, 1                   ; Syscall number for sys_write
    mov rdi, 1                   ; File descriptor for stdout
    lea rdx, [num_buffer]        ; Load the address of the string to print
    syscall

    inc rsi                      ; Increment the counter

    cmp rsi, 10000               ; Compare the counter with 10,000
    jle print_loop               ; Jump back to the loop if less than or equal

exit:
    mov rax, 60                  ; Syscall number for sys_exit
    xor rdi, rdi                 ; Exit status 0
    syscall

itoa:
    push rax                      ; Preserve registers
    push rdi
    push rdx

    mov rdi, rdx                 ; rdi points to the end of the buffer
    mov rcx, 10                  ; Set rcx to 10 (decimal)
    mov byte [rdi], 0            ; Null-terminate the string

itoa_loop:
    dec rdi
    xor rdx, rdx                 ; Clear any previous remainder
    div rcx                      ; Divide rax by 10
    add dl, '0'                  ; Convert the remainder to ASCII
    mov [rdi], dl                ; Store the ASCII character
    test rax, rax
    jnz itoa_loop

    pop rdx                       ; Restore registers
    pop rdi
    pop rax
    ret

strlen:
    push rax                      ; Preserve registers

    xor rax, rax                 ; Initialize length to 0
    xor rcx, rcx                 ; Initialize index to 0

strlen_loop:
    mov al, byte [rdi + rcx]     ; Load the next byte from the string
    test al, al                  ; Check if it's the null terminator
    jz strlen_done
    inc rax                       ; Increment the length
    inc rcx                       ; Increment the index
    jmp strlen_loop

strlen_done:
    pop rax                       ; Restore registers
    ret
```

```bash
vim Dockerfile
```

```dockerfile
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
```

### Build the image

```bash
 docker build -t number-printer .
```

### Run the container

```bash
docker run number-printer
```

### Result

```bash
❯ docker history number-printer
IMAGE          CREATED         CREATED BY                              SIZE      COMMENT
fe7b47c392f7   2 minutes ago   CMD ["/number_printer"]                 0B        buildkit.dockerfile.v0
<missing>      2 minutes ago   COPY /app/number_printer / # buildkit   9.11kB    buildkit.dockerfile.v0
```

```bash
 139 ❯ docker images
REPOSITORY                                                TAG                                                                          IMAGE ID       CREATED             SIZE
number-printer                                            latest                                                                       fe7b47c392f7   9 seconds ago       9.11kB
```

Assembly code is not working. I'm stuck on this error:

```bash
  main S:7 U:5 ?:4  ~/Ynov/B3/DevOps/wik-dps-tp02/bonus/assmebly                                                                                                                                                                                                                                                                                                                                             17:10:36  lexit 
❯ ./number_printer 
Segmentation fault (core dumped)
```