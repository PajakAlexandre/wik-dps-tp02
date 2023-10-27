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
```bash
❯ trivy rust_api_single_stage:1.0
2023-10-23T13:58:46.876+0200	INFO	Need to update DB
2023-10-23T13:58:46.876+0200	INFO	Downloading DB...
30.57 MiB / 30.57 MiB [---------------------------------------------------------------------------------------------------------------------------------------------------------------------] 100.00% 15.36 MiB p/s 2s
2023-10-23T13:58:54.078+0200	INFO	Detected OS: debian
2023-10-23T13:58:54.078+0200	INFO	Detecting Debian vulnerabilities...
2023-10-23T13:58:54.081+0200	INFO	Number of PL dependency files: 1
2023-10-23T13:58:54.081+0200	INFO	Detecting cargo vulnerabilities...

rust_api_single_stage:1.0 (debian 10.13)
========================================
Total: 120 (UNKNOWN: 2, LOW: 10, MEDIUM: 58, HIGH: 46, CRITICAL: 4)

+---------------+------------------+----------+------------------------+---------------+-----------------------------------------+
|    LIBRARY    | VULNERABILITY ID | SEVERITY |   INSTALLED VERSION    | FIXED VERSION |                  TITLE                  |
+---------------+------------------+----------+------------------------+---------------+-----------------------------------------+
| apt           | CVE-2011-3374    | LOW      | 1.8.2.3                |               | It was found that apt-key in apt,       |
|               |                  |          |                        |               | all versions, do not correctly...       |
|               |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2011-3374    |
+---------------+------------------+----------+------------------------+---------------+-----------------------------------------+
| bash          | CVE-2019-18276   | HIGH     | 5.0-4                  |               | bash: when effective UID is not         |
|               |                  |          |                        |               | equal to its real UID the...            |
|               |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2019-18276   |
+               +------------------+          +                        +---------------+-----------------------------------------+
|               | CVE-2022-3715    |          |                        |               | bash: a heap-buffer-overflow            |
|               |                  |          |                        |               | in valid_parameter_transform            |
|               |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2022-3715    |
+---------------+------------------+----------+------------------------+---------------+-----------------------------------------+
| bsdutils      | CVE-2021-37600   | MEDIUM   | 2.33.1-0.1             |               | util-linux: integer overflow            |
|               |                  |          |                        |               | can lead to buffer overflow             |
|               |                  |          |                        |               | in get_sem_elements() in                |
|               |                  |          |                        |               | sys-utils/ipcutils.c...                 |
|               |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2021-37600   |
+               +------------------+          +                        +---------------+-----------------------------------------+
|               | CVE-2022-0563    |          |                        |               | util-linux: partial disclosure          |
|               |                  |          |                        |               | of arbitrary files in chfn              |
|               |                  |          |                        |               | and chsh when compiled...               |
|               |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2022-0563    |
+---------------+------------------+          +------------------------+---------------+-----------------------------------------+
| coreutils     | CVE-2016-2781    |          | 8.30-3                 |               | coreutils: Non-privileged               |
|               |                  |          |                        |               | session can escape to the               |
|               |                  |          |                        |               | parent session in chroot                |
|               |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2016-2781    |
+               +------------------+          +                        +---------------+-----------------------------------------+
|               | CVE-2017-18018   |          |                        |               | coreutils: race condition               |
|               |                  |          |                        |               | vulnerability in chown and chgrp        |
|               |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2017-18018   |
+---------------+------------------+----------+------------------------+---------------+-----------------------------------------+
| e2fsprogs     | CVE-2022-1304    | HIGH     | 1.44.5-1+deb10u3       |               | e2fsprogs: out-of-bounds                |
|               |                  |          |                        |               | read/write via crafted filesystem       |
|               |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2022-1304    |
+---------------+------------------+----------+------------------------+---------------+-----------------------------------------+
| fdisk         | CVE-2021-37600   | MEDIUM   | 2.33.1-0.1             |               | util-linux: integer overflow            |
|               |                  |          |                        |               | can lead to buffer overflow             |
|               |                  |          |                        |               | in get_sem_elements() in                |
|               |                  |          |                        |               | sys-utils/ipcutils.c...                 |
|               |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2021-37600   |
+               +------------------+          +                        +---------------+-----------------------------------------+
|               | CVE-2022-0563    |          |                        |               | util-linux: partial disclosure          |
|               |                  |          |                        |               | of arbitrary files in chfn              |
|               |                  |          |                        |               | and chsh when compiled...               |
|               |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2022-0563    |
+---------------+------------------+----------+------------------------+---------------+-----------------------------------------+
| gcc-8-base    | CVE-2018-12886   | HIGH     | 8.3.0-6                |               | gcc: spilling of stack                  |
|               |                  |          |                        |               | protection address in cfgexpand.c       |
|               |                  |          |                        |               | and function.c leads to...              |
|               |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2018-12886   |
+               +------------------+          +                        +---------------+-----------------------------------------+
|               | CVE-2019-15847   |          |                        |               | gcc: POWER9 "DARN" RNG intrinsic        |
|               |                  |          |                        |               | produces repeated output                |
|               |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2019-15847   |
+---------------+------------------+          +------------------------+---------------+-----------------------------------------+
| gpgv          | CVE-2019-14855   |          | 2.2.12-1+deb10u2       |               | gnupg2: OpenPGP Key Certification       |
|               |                  |          |                        |               | Forgeries with SHA-1                    |
|               |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2019-14855   |
+---------------+------------------+----------+------------------------+---------------+-----------------------------------------+
| libapt-pkg5.0 | CVE-2011-3374    | LOW      | 1.8.2.3                |               | It was found that apt-key in apt,       |
|               |                  |          |                        |               | all versions, do not correctly...       |
|               |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2011-3374    |
+---------------+------------------+----------+------------------------+---------------+-----------------------------------------+
| libblkid1     | CVE-2021-37600   | MEDIUM   | 2.33.1-0.1             |               | util-linux: integer overflow            |
|               |                  |          |                        |               | can lead to buffer overflow             |
|               |                  |          |                        |               | in get_sem_elements() in                |
|               |                  |          |                        |               | sys-utils/ipcutils.c...                 |
|               |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2021-37600   |
+               +------------------+          +                        +---------------+-----------------------------------------+
|               | CVE-2022-0563    |          |                        |               | util-linux: partial disclosure          |
|               |                  |          |                        |               | of arbitrary files in chfn              |
|               |                  |          |                        |               | and chsh when compiled...               |
|               |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2022-0563    |
+---------------+------------------+----------+------------------------+---------------+-----------------------------------------+
| libc-bin      | CVE-2019-1010022 | CRITICAL | 2.28-10+deb10u2        |               | glibc: stack guard protection bypass    |
|               |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2019-1010022 |
+               +------------------+----------+                        +---------------+-----------------------------------------+
|               | CVE-2018-20796   | HIGH     |                        |               | glibc: uncontrolled recursion in        |
|               |                  |          |                        |               | function check_dst_limits_calc_pos_1    |
|               |                  |          |                        |               | in posix/regexec.c                      |
|               |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2018-20796   |
+               +------------------+          +                        +---------------+-----------------------------------------+
|               | CVE-2019-1010023 |          |                        |               | glibc: running ldd on malicious ELF     |
|               |                  |          |                        |               | leads to code execution because of...   |
|               |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2019-1010023 |
+               +------------------+          +                        +---------------+-----------------------------------------+
|               | CVE-2019-9192    |          |                        |               | glibc: uncontrolled recursion in        |
|               |                  |          |                        |               | function check_dst_limits_calc_pos_1    |
|               |                  |          |                        |               | in posix/regexec.c                      |
|               |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2019-9192    |
+               +------------------+          +                        +---------------+-----------------------------------------+
|               | CVE-2020-1751    |          |                        |               | glibc: array overflow in                |
|               |                  |          |                        |               | backtrace functions for powerpc         |
|               |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2020-1751    |
+               +------------------+----------+                        +---------------+-----------------------------------------+
|               | CVE-2010-4756    | MEDIUM   |                        |               | glibc: glob implementation              |
|               |                  |          |                        |               | can cause excessive CPU and             |
|               |                  |          |                        |               | memory consumption due to...            |
|               |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2010-4756    |
+               +------------------+          +                        +---------------+-----------------------------------------+
|               | CVE-2019-1010024 |          |                        |               | glibc: ASLR bypass using                |
|               |                  |          |                        |               | cache of thread stack and heap          |
|               |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2019-1010024 |
+               +------------------+          +                        +---------------+-----------------------------------------+
|               | CVE-2019-1010025 |          |                        |               | glibc: information disclosure of heap   |
|               |                  |          |                        |               | addresses of pthread_created thread     |
|               |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2019-1010025 |
+---------------+------------------+----------+                        +---------------+-----------------------------------------+
| libc6         | CVE-2019-1010022 | CRITICAL |                        |               | glibc: stack guard protection bypass    |
|               |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2019-1010022 |
+               +------------------+----------+                        +---------------+-----------------------------------------+
|               | CVE-2018-20796   | HIGH     |                        |               | glibc: uncontrolled recursion in        |
|               |                  |          |                        |               | function check_dst_limits_calc_pos_1    |
|               |                  |          |                        |               | in posix/regexec.c                      |
|               |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2018-20796   |
+               +------------------+          +                        +---------------+-----------------------------------------+
|               | CVE-2019-1010023 |          |                        |               | glibc: running ldd on malicious ELF     |
|               |                  |          |                        |               | leads to code execution because of...   |
|               |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2019-1010023 |
+               +------------------+          +                        +---------------+-----------------------------------------+
|               | CVE-2019-9192    |          |                        |               | glibc: uncontrolled recursion in        |
|               |                  |          |                        |               | function check_dst_limits_calc_pos_1    |
|               |                  |          |                        |               | in posix/regexec.c                      |
|               |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2019-9192    |
+               +------------------+          +                        +---------------+-----------------------------------------+
|               | CVE-2020-1751    |          |                        |               | glibc: array overflow in                |
|               |                  |          |                        |               | backtrace functions for powerpc         |
|               |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2020-1751    |
+               +------------------+----------+                        +---------------+-----------------------------------------+
|               | CVE-2010-4756    | MEDIUM   |                        |               | glibc: glob implementation              |
|               |                  |          |                        |               | can cause excessive CPU and             |
|               |                  |          |                        |               | memory consumption due to...            |
|               |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2010-4756    |
+               +------------------+          +                        +---------------+-----------------------------------------+
|               | CVE-2019-1010024 |          |                        |               | glibc: ASLR bypass using                |
|               |                  |          |                        |               | cache of thread stack and heap          |
|               |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2019-1010024 |
+               +------------------+          +                        +---------------+-----------------------------------------+
|               | CVE-2019-1010025 |          |                        |               | glibc: information disclosure of heap   |
|               |                  |          |                        |               | addresses of pthread_created thread     |
|               |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2019-1010025 |
+---------------+------------------+----------+------------------------+---------------+-----------------------------------------+
| libcom-err2   | CVE-2022-1304    | HIGH     | 1.44.5-1+deb10u3       |               | e2fsprogs: out-of-bounds                |
|               |                  |          |                        |               | read/write via crafted filesystem       |
|               |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2022-1304    |
+---------------+------------------+----------+------------------------+---------------+-----------------------------------------+
| libdb5.3      | CVE-2019-8457    | CRITICAL | 5.3.28+dfsg1-0.5       |               | sqlite: heap out-of-bound               |
|               |                  |          |                        |               | read in function rtreenode()            |
|               |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2019-8457    |
+---------------+------------------+----------+------------------------+---------------+-----------------------------------------+
| libext2fs2    | CVE-2022-1304    | HIGH     | 1.44.5-1+deb10u3       |               | e2fsprogs: out-of-bounds                |
|               |                  |          |                        |               | read/write via crafted filesystem       |
|               |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2022-1304    |
+---------------+------------------+----------+------------------------+---------------+-----------------------------------------+
| libfdisk1     | CVE-2021-37600   | MEDIUM   | 2.33.1-0.1             |               | util-linux: integer overflow            |
|               |                  |          |                        |               | can lead to buffer overflow             |
|               |                  |          |                        |               | in get_sem_elements() in                |
|               |                  |          |                        |               | sys-utils/ipcutils.c...                 |
|               |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2021-37600   |
+               +------------------+          +                        +---------------+-----------------------------------------+
|               | CVE-2022-0563    |          |                        |               | util-linux: partial disclosure          |
|               |                  |          |                        |               | of arbitrary files in chfn              |
|               |                  |          |                        |               | and chsh when compiled...               |
|               |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2022-0563    |
+---------------+------------------+----------+------------------------+---------------+-----------------------------------------+
| libgcc1       | CVE-2018-12886   | HIGH     | 8.3.0-6                |               | gcc: spilling of stack                  |
|               |                  |          |                        |               | protection address in cfgexpand.c       |
|               |                  |          |                        |               | and function.c leads to...              |
|               |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2018-12886   |
+               +------------------+          +                        +---------------+-----------------------------------------+
|               | CVE-2019-15847   |          |                        |               | gcc: POWER9 "DARN" RNG intrinsic        |
|               |                  |          |                        |               | produces repeated output                |
|               |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2019-15847   |
+---------------+------------------+          +------------------------+---------------+-----------------------------------------+
| libgcrypt20   | CVE-2018-6829    |          | 1.8.4-5+deb10u1        |               | libgcrypt: ElGamal implementation       |
|               |                  |          |                        |               | doesn't have semantic security due      |
|               |                  |          |                        |               | to incorrectly encoded plaintexts...    |
|               |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2018-6829    |
+               +------------------+          +                        +---------------+-----------------------------------------+
|               | CVE-2021-33560   |          |                        |               | libgcrypt: mishandles ElGamal           |
|               |                  |          |                        |               | encryption because it lacks             |
|               |                  |          |                        |               | exponent blinding to address a...       |
|               |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2021-33560   |
+               +------------------+----------+                        +---------------+-----------------------------------------+
|               | CVE-2019-13627   | MEDIUM   |                        |               | libgcrypt: ECDSA timing attack          |
|               |                  |          |                        |               | allowing private key leak               |
|               |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2019-13627   |
+---------------+------------------+          +------------------------+---------------+-----------------------------------------+
| libgnutls30   | CVE-2011-3389    |          | 3.6.7-4+deb10u10       |               | HTTPS: block-wise chosen-plaintext      |
|               |                  |          |                        |               | attack against SSL/TLS (BEAST)          |
|               |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2011-3389    |
+---------------+------------------+----------+------------------------+---------------+-----------------------------------------+
| libidn2-0     | CVE-2019-12290   | HIGH     | 2.0.5-1+deb10u1        |               | GNU libidn2 before 2.2.0                |
|               |                  |          |                        |               | fails to perform the roundtrip          |
|               |                  |          |                        |               | checks specified in...                  |
|               |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2019-12290   |
+---------------+------------------+          +------------------------+---------------+-----------------------------------------+
| liblz4-1      | CVE-2019-17543   |          | 1.8.3-1+deb10u1        |               | lz4: heap-based buffer                  |
|               |                  |          |                        |               | overflow in LZ4_write32                 |
|               |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2019-17543   |
+---------------+------------------+----------+------------------------+---------------+-----------------------------------------+
| libmount1     | CVE-2021-37600   | MEDIUM   | 2.33.1-0.1             |               | util-linux: integer overflow            |
|               |                  |          |                        |               | can lead to buffer overflow             |
|               |                  |          |                        |               | in get_sem_elements() in                |
|               |                  |          |                        |               | sys-utils/ipcutils.c...                 |
|               |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2021-37600   |
+               +------------------+          +                        +---------------+-----------------------------------------+
|               | CVE-2022-0563    |          |                        |               | util-linux: partial disclosure          |
|               |                  |          |                        |               | of arbitrary files in chfn              |
|               |                  |          |                        |               | and chsh when compiled...               |
|               |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2022-0563    |
+---------------+------------------+----------+------------------------+---------------+-----------------------------------------+
| libncursesw6  | CVE-2021-39537   | HIGH     | 6.1+20181013-2+deb10u4 |               | ncurses: heap-based buffer overflow     |
|               |                  |          |                        |               | in _nc_captoinfo() in captoinfo.c       |
|               |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2021-39537   |
+---------------+------------------+          +------------------------+---------------+-----------------------------------------+
| libpcre3      | CVE-2017-11164   |          | 2:8.39-12              |               | pcre: OP_KETRMAX feature in the         |
|               |                  |          |                        |               | match function in pcre_exec.c           |
|               |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2017-11164   |
+               +------------------+          +                        +---------------+-----------------------------------------+
|               | CVE-2017-7245    |          |                        |               | pcre: stack-based buffer overflow       |
|               |                  |          |                        |               | write in pcre32_copy_substring          |
|               |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2017-7245    |
+               +------------------+          +                        +---------------+-----------------------------------------+
|               | CVE-2017-7246    |          |                        |               | pcre: stack-based buffer overflow       |
|               |                  |          |                        |               | write in pcre32_copy_substring          |
|               |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2017-7246    |
+               +------------------+          +                        +---------------+-----------------------------------------+
|               | CVE-2019-20838   |          |                        |               | pcre: Buffer over-read in JIT           |
|               |                  |          |                        |               | when UTF is disabled and \X or...       |
|               |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2019-20838   |
+               +------------------+----------+                        +---------------+-----------------------------------------+
|               | CVE-2017-16231   | MEDIUM   |                        |               | pcre: self-recursive call               |
|               |                  |          |                        |               | in match() in pcre_exec.c               |
|               |                  |          |                        |               | leads to denial of service...           |
|               |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2017-16231   |
+               +------------------+          +                        +---------------+-----------------------------------------+
|               | CVE-2020-14155   |          |                        |               | pcre: Integer overflow when             |
|               |                  |          |                        |               | parsing callout numeric arguments       |
|               |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2020-14155   |
+---------------+------------------+----------+------------------------+---------------+-----------------------------------------+
| libseccomp2   | CVE-2019-9893    | CRITICAL | 2.3.3-4                |               | libseccomp: incorrect generation        |
|               |                  |          |                        |               | of syscall filters in libseccomp        |
|               |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2019-9893    |
+---------------+------------------+----------+------------------------+---------------+-----------------------------------------+
| libsepol1     | CVE-2021-36084   | LOW      | 2.8-1                  |               | libsepol: use-after-free in             |
|               |                  |          |                        |               | __cil_verify_classperms()               |
|               |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2021-36084   |
+               +------------------+          +                        +---------------+-----------------------------------------+
|               | CVE-2021-36085   |          |                        |               | libsepol: use-after-free in             |
|               |                  |          |                        |               | __cil_verify_classperms()               |
|               |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2021-36085   |
+               +------------------+          +                        +---------------+-----------------------------------------+
|               | CVE-2021-36086   |          |                        |               | libsepol: use-after-free in             |
|               |                  |          |                        |               | cil_reset_classpermission()             |
|               |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2021-36086   |
+               +------------------+          +                        +---------------+-----------------------------------------+
|               | CVE-2021-36087   |          |                        |               | libsepol: heap-based buffer             |
|               |                  |          |                        |               | overflow in ebitmap_match_any()         |
|               |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2021-36087   |
+---------------+------------------+----------+------------------------+---------------+-----------------------------------------+
| libsmartcols1 | CVE-2021-37600   | MEDIUM   | 2.33.1-0.1             |               | util-linux: integer overflow            |
|               |                  |          |                        |               | can lead to buffer overflow             |
|               |                  |          |                        |               | in get_sem_elements() in                |
|               |                  |          |                        |               | sys-utils/ipcutils.c...                 |
|               |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2021-37600   |
+               +------------------+          +                        +---------------+-----------------------------------------+
|               | CVE-2022-0563    |          |                        |               | util-linux: partial disclosure          |
|               |                  |          |                        |               | of arbitrary files in chfn              |
|               |                  |          |                        |               | and chsh when compiled...               |
|               |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2022-0563    |
+---------------+------------------+----------+------------------------+---------------+-----------------------------------------+
| libss2        | CVE-2022-1304    | HIGH     | 1.44.5-1+deb10u3       |               | e2fsprogs: out-of-bounds                |
|               |                  |          |                        |               | read/write via crafted filesystem       |
|               |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2022-1304    |
+---------------+------------------+          +------------------------+---------------+-----------------------------------------+
| libssl1.1     | CVE-2023-0286    |          | 1.1.1n-0+deb10u6       |               | X.400 address type confusion            |
|               |                  |          |                        |               | in X.509 GeneralName                    |
|               |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2023-0286    |
+               +------------------+----------+                        +---------------+-----------------------------------------+
|               | CVE-2007-6755    | MEDIUM   |                        |               | Dual_EC_DRBG: weak pseudo               |
|               |                  |          |                        |               | random number generator                 |
|               |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2007-6755    |
+               +------------------+          +                        +---------------+-----------------------------------------+
|               | CVE-2010-0928    |          |                        |               | openssl: RSA authentication weakness    |
|               |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2010-0928    |
+               +------------------+          +                        +---------------+-----------------------------------------+
|               | CVE-2022-2097    |          |                        |               | openssl: AES OCB fails                  |
|               |                  |          |                        |               | to encrypt some bytes                   |
|               |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2022-2097    |
+               +------------------+          +                        +---------------+-----------------------------------------+
|               | CVE-2022-4304    |          |                        |               | Timing Oracle in RSA Decryption         |
|               |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2022-4304    |
+               +------------------+          +                        +---------------+-----------------------------------------+
|               | CVE-2022-4450    |          |                        |               | Double free after                       |
|               |                  |          |                        |               | calling PEM_read_bio_ex                 |
|               |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2022-4450    |
+               +------------------+          +                        +---------------+-----------------------------------------+
|               | CVE-2023-0215    |          |                        |               | Use-after-free                          |
|               |                  |          |                        |               | following BIO_new_NDEF                  |
|               |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2023-0215    |
+---------------+------------------+----------+------------------------+---------------+-----------------------------------------+
| libstdc++6    | CVE-2018-12886   | HIGH     | 8.3.0-6                |               | gcc: spilling of stack                  |
|               |                  |          |                        |               | protection address in cfgexpand.c       |
|               |                  |          |                        |               | and function.c leads to...              |
|               |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2018-12886   |
+               +------------------+          +                        +---------------+-----------------------------------------+
|               | CVE-2019-15847   |          |                        |               | gcc: POWER9 "DARN" RNG intrinsic        |
|               |                  |          |                        |               | produces repeated output                |
|               |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2019-15847   |
+---------------+------------------+          +------------------------+---------------+-----------------------------------------+
| libsystemd0   | CVE-2019-3843    |          | 241-7~deb10u10         |               | systemd: services with DynamicUser      |
|               |                  |          |                        |               | can create SUID/SGID binaries           |
|               |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2019-3843    |
+               +------------------+          +                        +---------------+-----------------------------------------+
|               | CVE-2019-3844    |          |                        |               | systemd: services with DynamicUser      |
|               |                  |          |                        |               | can get new privileges and              |
|               |                  |          |                        |               | create SGID binaries...                 |
|               |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2019-3844    |
+               +------------------+----------+                        +---------------+-----------------------------------------+
|               | CVE-2020-13529   | MEDIUM   |                        |               | systemd: DHCP FORCERENEW                |
|               |                  |          |                        |               | authentication not implemented          |
|               |                  |          |                        |               | can cause a system running the...       |
|               |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2020-13529   |
+               +------------------+          +                        +---------------+-----------------------------------------+
|               | CVE-2021-3997    |          |                        |               | systemd: Uncontrolled recursion in      |
|               |                  |          |                        |               | systemd-tmpfiles when removing files    |
|               |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2021-3997    |
+               +------------------+          +                        +---------------+-----------------------------------------+
|               | CVE-2022-3821    |          |                        |               | systemd: buffer overrun in              |
|               |                  |          |                        |               | format_timespan() function              |
|               |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2022-3821    |
+               +------------------+          +                        +---------------+-----------------------------------------+
|               | CVE-2022-4415    |          |                        |               | systemd: local information leak due     |
|               |                  |          |                        |               | to systemd-coredump not respecting      |
|               |                  |          |                        |               | fs.suid_dumpable kernel setting...      |
|               |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2022-4415    |
+               +------------------+----------+                        +---------------+-----------------------------------------+
|               | CVE-2013-4392    | LOW      |                        |               | systemd: TOCTOU race condition          |
|               |                  |          |                        |               | when updating file permissions          |
|               |                  |          |                        |               | and SELinux security contexts...        |
|               |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2013-4392    |
+               +------------------+          +                        +---------------+-----------------------------------------+
|               | CVE-2019-20386   |          |                        |               | systemd: memory leak in button_open()   |
|               |                  |          |                        |               | in login/logind-button.c when           |
|               |                  |          |                        |               | udev events are received...             |
|               |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2019-20386   |
+---------------+------------------+----------+------------------------+---------------+-----------------------------------------+
| libtasn1-6    | CVE-2018-1000654 | MEDIUM   | 4.13-3+deb10u1         |               | libtasn1: Infinite loop in              |
|               |                  |          |                        |               | _asn1_expand_object_id(ptree)           |
|               |                  |          |                        |               | leads to memory exhaustion              |
|               |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2018-1000654 |
+---------------+------------------+----------+------------------------+---------------+-----------------------------------------+
| libtinfo6     | CVE-2021-39537   | HIGH     | 6.1+20181013-2+deb10u4 |               | ncurses: heap-based buffer overflow     |
|               |                  |          |                        |               | in _nc_captoinfo() in captoinfo.c       |
|               |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2021-39537   |
+---------------+------------------+          +------------------------+---------------+-----------------------------------------+
| libudev1      | CVE-2019-3843    |          | 241-7~deb10u10         |               | systemd: services with DynamicUser      |
|               |                  |          |                        |               | can create SUID/SGID binaries           |
|               |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2019-3843    |
+               +------------------+          +                        +---------------+-----------------------------------------+
|               | CVE-2019-3844    |          |                        |               | systemd: services with DynamicUser      |
|               |                  |          |                        |               | can get new privileges and              |
|               |                  |          |                        |               | create SGID binaries...                 |
|               |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2019-3844    |
+               +------------------+----------+                        +---------------+-----------------------------------------+
|               | CVE-2020-13529   | MEDIUM   |                        |               | systemd: DHCP FORCERENEW                |
|               |                  |          |                        |               | authentication not implemented          |
|               |                  |          |                        |               | can cause a system running the...       |
|               |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2020-13529   |
+               +------------------+          +                        +---------------+-----------------------------------------+
|               | CVE-2021-3997    |          |                        |               | systemd: Uncontrolled recursion in      |
|               |                  |          |                        |               | systemd-tmpfiles when removing files    |
|               |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2021-3997    |
+               +------------------+          +                        +---------------+-----------------------------------------+
|               | CVE-2022-3821    |          |                        |               | systemd: buffer overrun in              |
|               |                  |          |                        |               | format_timespan() function              |
|               |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2022-3821    |
+               +------------------+          +                        +---------------+-----------------------------------------+
|               | CVE-2022-4415    |          |                        |               | systemd: local information leak due     |
|               |                  |          |                        |               | to systemd-coredump not respecting      |
|               |                  |          |                        |               | fs.suid_dumpable kernel setting...      |
|               |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2022-4415    |
+               +------------------+----------+                        +---------------+-----------------------------------------+
|               | CVE-2013-4392    | LOW      |                        |               | systemd: TOCTOU race condition          |
|               |                  |          |                        |               | when updating file permissions          |
|               |                  |          |                        |               | and SELinux security contexts...        |
|               |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2013-4392    |
+               +------------------+          +                        +---------------+-----------------------------------------+
|               | CVE-2019-20386   |          |                        |               | systemd: memory leak in button_open()   |
|               |                  |          |                        |               | in login/logind-button.c when           |
|               |                  |          |                        |               | udev events are received...             |
|               |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2019-20386   |
+---------------+------------------+----------+------------------------+---------------+-----------------------------------------+
| libuuid1      | CVE-2021-37600   | MEDIUM   | 2.33.1-0.1             |               | util-linux: integer overflow            |
|               |                  |          |                        |               | can lead to buffer overflow             |
|               |                  |          |                        |               | in get_sem_elements() in                |
|               |                  |          |                        |               | sys-utils/ipcutils.c...                 |
|               |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2021-37600   |
+               +------------------+          +                        +---------------+-----------------------------------------+
|               | CVE-2022-0563    |          |                        |               | util-linux: partial disclosure          |
|               |                  |          |                        |               | of arbitrary files in chfn              |
|               |                  |          |                        |               | and chsh when compiled...               |
|               |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2022-0563    |
+---------------+------------------+----------+------------------------+---------------+-----------------------------------------+
| login         | CVE-2019-19882   | HIGH     | 1:4.5-1.1              |               | shadow-utils: local users can           |
|               |                  |          |                        |               | obtain root access because setuid       |
|               |                  |          |                        |               | programs are misconfigured...           |
|               |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2019-19882   |
+               +------------------+----------+                        +---------------+-----------------------------------------+
|               | CVE-2007-5686    | MEDIUM   |                        |               | initscripts in rPath Linux 1            |
|               |                  |          |                        |               | sets insecure permissions for           |
|               |                  |          |                        |               | the /var/log/btmp file,...              |
|               |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2007-5686    |
+               +------------------+          +                        +---------------+-----------------------------------------+
|               | CVE-2013-4235    |          |                        |               | shadow-utils: TOCTOU race               |
|               |                  |          |                        |               | conditions by copying and               |
|               |                  |          |                        |               | removing directory trees                |
|               |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2013-4235    |
+               +------------------+          +                        +---------------+-----------------------------------------+
|               | CVE-2018-7169    |          |                        |               | shadow-utils: newgidmap                 |
|               |                  |          |                        |               | allows unprivileged user to             |
|               |                  |          |                        |               | drop supplementary groups               |
|               |                  |          |                        |               | potentially allowing privilege...       |
|               |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2018-7169    |
+               +------------------+----------+                        +---------------+-----------------------------------------+
|               | CVE-2023-0634    | UNKNOWN  |                        |               | An uncontrolled process                 |
|               |                  |          |                        |               | operation was found in the              |
|               |                  |          |                        |               | newgrp command provided by...           |
|               |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2023-0634    |
+---------------+------------------+----------+------------------------+---------------+-----------------------------------------+
| mount         | CVE-2021-37600   | MEDIUM   | 2.33.1-0.1             |               | util-linux: integer overflow            |
|               |                  |          |                        |               | can lead to buffer overflow             |
|               |                  |          |                        |               | in get_sem_elements() in                |
|               |                  |          |                        |               | sys-utils/ipcutils.c...                 |
|               |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2021-37600   |
+               +------------------+          +                        +---------------+-----------------------------------------+
|               | CVE-2022-0563    |          |                        |               | util-linux: partial disclosure          |
|               |                  |          |                        |               | of arbitrary files in chfn              |
|               |                  |          |                        |               | and chsh when compiled...               |
|               |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2022-0563    |
+---------------+------------------+----------+------------------------+---------------+-----------------------------------------+
| ncurses-base  | CVE-2021-39537   | HIGH     | 6.1+20181013-2+deb10u4 |               | ncurses: heap-based buffer overflow     |
|               |                  |          |                        |               | in _nc_captoinfo() in captoinfo.c       |
|               |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2021-39537   |
+---------------+                  +          +                        +---------------+                                         +
| ncurses-bin   |                  |          |                        |               |                                         |
|               |                  |          |                        |               |                                         |
|               |                  |          |                        |               |                                         |
+---------------+------------------+          +------------------------+---------------+-----------------------------------------+
| openssl       | CVE-2023-0286    |          | 1.1.1n-0+deb10u6       |               | X.400 address type confusion            |
|               |                  |          |                        |               | in X.509 GeneralName                    |
|               |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2023-0286    |
+               +------------------+----------+                        +---------------+-----------------------------------------+
|               | CVE-2007-6755    | MEDIUM   |                        |               | Dual_EC_DRBG: weak pseudo               |
|               |                  |          |                        |               | random number generator                 |
|               |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2007-6755    |
+               +------------------+          +                        +---------------+-----------------------------------------+
|               | CVE-2010-0928    |          |                        |               | openssl: RSA authentication weakness    |
|               |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2010-0928    |
+               +------------------+          +                        +---------------+-----------------------------------------+
|               | CVE-2022-2097    |          |                        |               | openssl: AES OCB fails                  |
|               |                  |          |                        |               | to encrypt some bytes                   |
|               |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2022-2097    |
+               +------------------+          +                        +---------------+-----------------------------------------+
|               | CVE-2022-4304    |          |                        |               | Timing Oracle in RSA Decryption         |
|               |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2022-4304    |
+               +------------------+          +                        +---------------+-----------------------------------------+
|               | CVE-2022-4450    |          |                        |               | Double free after                       |
|               |                  |          |                        |               | calling PEM_read_bio_ex                 |
|               |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2022-4450    |
+               +------------------+          +                        +---------------+-----------------------------------------+
|               | CVE-2023-0215    |          |                        |               | Use-after-free                          |
|               |                  |          |                        |               | following BIO_new_NDEF                  |
|               |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2023-0215    |
+---------------+------------------+----------+------------------------+---------------+-----------------------------------------+
| passwd        | CVE-2019-19882   | HIGH     | 1:4.5-1.1              |               | shadow-utils: local users can           |
|               |                  |          |                        |               | obtain root access because setuid       |
|               |                  |          |                        |               | programs are misconfigured...           |
|               |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2019-19882   |
+               +------------------+----------+                        +---------------+-----------------------------------------+
|               | CVE-2007-5686    | MEDIUM   |                        |               | initscripts in rPath Linux 1            |
|               |                  |          |                        |               | sets insecure permissions for           |
|               |                  |          |                        |               | the /var/log/btmp file,...              |
|               |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2007-5686    |
+               +------------------+          +                        +---------------+-----------------------------------------+
|               | CVE-2013-4235    |          |                        |               | shadow-utils: TOCTOU race               |
|               |                  |          |                        |               | conditions by copying and               |
|               |                  |          |                        |               | removing directory trees                |
|               |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2013-4235    |
+               +------------------+          +                        +---------------+-----------------------------------------+
|               | CVE-2018-7169    |          |                        |               | shadow-utils: newgidmap                 |
|               |                  |          |                        |               | allows unprivileged user to             |
|               |                  |          |                        |               | drop supplementary groups               |
|               |                  |          |                        |               | potentially allowing privilege...       |
|               |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2018-7169    |
+               +------------------+----------+                        +---------------+-----------------------------------------+
|               | CVE-2023-0634    | UNKNOWN  |                        |               | An uncontrolled process                 |
|               |                  |          |                        |               | operation was found in the              |
|               |                  |          |                        |               | newgrp command provided by...           |
|               |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2023-0634    |
+---------------+------------------+----------+------------------------+---------------+-----------------------------------------+
| perl-base     | CVE-2011-4116    | HIGH     | 5.28.1-6+deb10u1       |               | perl: File::Temp insecure               |
|               |                  |          |                        |               | temporary file handling                 |
|               |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2011-4116    |
+               +------------------+          +                        +---------------+-----------------------------------------+
|               | CVE-2020-16156   |          |                        |               | perl-CPAN: Bypass of verification       |
|               |                  |          |                        |               | of signatures in CHECKSUMS files        |
|               |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2020-16156   |
+---------------+------------------+          +------------------------+---------------+-----------------------------------------+
| tar           | CVE-2005-2541    |          | 1.30+dfsg-6            |               | tar: does not properly warn the user    |
|               |                  |          |                        |               | when extracting setuid or setgid...     |
|               |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2005-2541    |
+               +------------------+          +                        +---------------+-----------------------------------------+
|               | CVE-2019-9923    |          |                        |               | tar: null-pointer dereference           |
|               |                  |          |                        |               | in pax_decode_header in sparse.c        |
|               |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2019-9923    |
+               +------------------+          +                        +---------------+-----------------------------------------+
|               | CVE-2022-48303   |          |                        |               | tar: a heap buffer overflow             |
|               |                  |          |                        |               | at from_header() in list.c              |
|               |                  |          |                        |               | via specially crafter...                |
|               |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2022-48303   |
+               +------------------+----------+                        +---------------+-----------------------------------------+
|               | CVE-2021-20193   | MEDIUM   |                        |               | tar: Memory leak in                     |
|               |                  |          |                        |               | read_header() in list.c                 |
|               |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2021-20193   |
+---------------+------------------+          +------------------------+---------------+-----------------------------------------+
| util-linux    | CVE-2021-37600   |          | 2.33.1-0.1             |               | util-linux: integer overflow            |
|               |                  |          |                        |               | can lead to buffer overflow             |
|               |                  |          |                        |               | in get_sem_elements() in                |
|               |                  |          |                        |               | sys-utils/ipcutils.c...                 |
|               |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2021-37600   |
+               +------------------+          +                        +---------------+-----------------------------------------+
|               | CVE-2022-0563    |          |                        |               | util-linux: partial disclosure          |
|               |                  |          |                        |               | of arbitrary files in chfn              |
|               |                  |          |                        |               | and chsh when compiled...               |
|               |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2022-0563    |
+---------------+------------------+----------+------------------------+---------------+-----------------------------------------+

app/Cargo.lock
==============
Total: 0 (UNKNOWN: 0, LOW: 0, MEDIUM: 0, HIGH: 0, CRITICAL: 0)


```


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

```bash
 ~/Ynov/DevOps/wik-dps-tp02/rust_api                                                                                                                                                               12:06:48  lexit 
❯ trivy rust_api:1.0
2023-10-23T12:08:52.205+0200	INFO	Need to update DB
2023-10-23T12:08:52.205+0200	INFO	Downloading DB...
30.57 MiB / 30.57 MiB [---------------------------------------------------------------------------------------------------------------------------------------------------------------------] 100.00% 17.17 MiB p/s 2s
2023-10-23T12:08:55.002+0200	INFO	Detected OS: debian
2023-10-23T12:08:55.002+0200	INFO	Detecting Debian vulnerabilities...
2023-10-23T12:08:55.004+0200	INFO	Number of PL dependency files: 0

rust_api:1.0 (debian 10.13)
===========================
Total: 106 (UNKNOWN: 2, LOW: 10, MEDIUM: 46, HIGH: 44, CRITICAL: 4)

+---------------+------------------+----------+------------------------+---------------+-----------------------------------------+
|    LIBRARY    | VULNERABILITY ID | SEVERITY |   INSTALLED VERSION    | FIXED VERSION |                  TITLE                  |
+---------------+------------------+----------+------------------------+---------------+-----------------------------------------+
| apt           | CVE-2011-3374    | LOW      | 1.8.2.3                |               | It was found that apt-key in apt,       |
|               |                  |          |                        |               | all versions, do not correctly...       |
|               |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2011-3374    |
+---------------+------------------+----------+------------------------+---------------+-----------------------------------------+
| bash          | CVE-2019-18276   | HIGH     | 5.0-4                  |               | bash: when effective UID is not         |
|               |                  |          |                        |               | equal to its real UID the...            |
|               |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2019-18276   |
+               +------------------+          +                        +---------------+-----------------------------------------+
|               | CVE-2022-3715    |          |                        |               | bash: a heap-buffer-overflow            |
|               |                  |          |                        |               | in valid_parameter_transform            |
|               |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2022-3715    |
+---------------+------------------+----------+------------------------+---------------+-----------------------------------------+
| bsdutils      | CVE-2021-37600   | MEDIUM   | 2.33.1-0.1             |               | util-linux: integer overflow            |
|               |                  |          |                        |               | can lead to buffer overflow             |
|               |                  |          |                        |               | in get_sem_elements() in                |
|               |                  |          |                        |               | sys-utils/ipcutils.c...                 |
|               |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2021-37600   |
+               +------------------+          +                        +---------------+-----------------------------------------+
|               | CVE-2022-0563    |          |                        |               | util-linux: partial disclosure          |
|               |                  |          |                        |               | of arbitrary files in chfn              |
|               |                  |          |                        |               | and chsh when compiled...               |
|               |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2022-0563    |
+---------------+------------------+          +------------------------+---------------+-----------------------------------------+
| coreutils     | CVE-2016-2781    |          | 8.30-3                 |               | coreutils: Non-privileged               |
|               |                  |          |                        |               | session can escape to the               |
|               |                  |          |                        |               | parent session in chroot                |
|               |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2016-2781    |
+               +------------------+          +                        +---------------+-----------------------------------------+
|               | CVE-2017-18018   |          |                        |               | coreutils: race condition               |
|               |                  |          |                        |               | vulnerability in chown and chgrp        |
|               |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2017-18018   |
+---------------+------------------+----------+------------------------+---------------+-----------------------------------------+
| e2fsprogs     | CVE-2022-1304    | HIGH     | 1.44.5-1+deb10u3       |               | e2fsprogs: out-of-bounds                |
|               |                  |          |                        |               | read/write via crafted filesystem       |
|               |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2022-1304    |
+---------------+------------------+----------+------------------------+---------------+-----------------------------------------+
| fdisk         | CVE-2021-37600   | MEDIUM   | 2.33.1-0.1             |               | util-linux: integer overflow            |
|               |                  |          |                        |               | can lead to buffer overflow             |
|               |                  |          |                        |               | in get_sem_elements() in                |
|               |                  |          |                        |               | sys-utils/ipcutils.c...                 |
|               |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2021-37600   |
+               +------------------+          +                        +---------------+-----------------------------------------+
|               | CVE-2022-0563    |          |                        |               | util-linux: partial disclosure          |
|               |                  |          |                        |               | of arbitrary files in chfn              |
|               |                  |          |                        |               | and chsh when compiled...               |
|               |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2022-0563    |
+---------------+------------------+----------+------------------------+---------------+-----------------------------------------+
| gcc-8-base    | CVE-2018-12886   | HIGH     | 8.3.0-6                |               | gcc: spilling of stack                  |
|               |                  |          |                        |               | protection address in cfgexpand.c       |
|               |                  |          |                        |               | and function.c leads to...              |
|               |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2018-12886   |
+               +------------------+          +                        +---------------+-----------------------------------------+
|               | CVE-2019-15847   |          |                        |               | gcc: POWER9 "DARN" RNG intrinsic        |
|               |                  |          |                        |               | produces repeated output                |
|               |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2019-15847   |
+---------------+------------------+          +------------------------+---------------+-----------------------------------------+
| gpgv          | CVE-2019-14855   |          | 2.2.12-1+deb10u2       |               | gnupg2: OpenPGP Key Certification       |
|               |                  |          |                        |               | Forgeries with SHA-1                    |
|               |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2019-14855   |
+---------------+------------------+----------+------------------------+---------------+-----------------------------------------+
| libapt-pkg5.0 | CVE-2011-3374    | LOW      | 1.8.2.3                |               | It was found that apt-key in apt,       |
|               |                  |          |                        |               | all versions, do not correctly...       |
|               |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2011-3374    |
+---------------+------------------+----------+------------------------+---------------+-----------------------------------------+
| libblkid1     | CVE-2021-37600   | MEDIUM   | 2.33.1-0.1             |               | util-linux: integer overflow            |
|               |                  |          |                        |               | can lead to buffer overflow             |
|               |                  |          |                        |               | in get_sem_elements() in                |
|               |                  |          |                        |               | sys-utils/ipcutils.c...                 |
|               |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2021-37600   |
+               +------------------+          +                        +---------------+-----------------------------------------+
|               | CVE-2022-0563    |          |                        |               | util-linux: partial disclosure          |
|               |                  |          |                        |               | of arbitrary files in chfn              |
|               |                  |          |                        |               | and chsh when compiled...               |
|               |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2022-0563    |
+---------------+------------------+----------+------------------------+---------------+-----------------------------------------+
| libc-bin      | CVE-2019-1010022 | CRITICAL | 2.28-10+deb10u2        |               | glibc: stack guard protection bypass    |
|               |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2019-1010022 |
+               +------------------+----------+                        +---------------+-----------------------------------------+
|               | CVE-2018-20796   | HIGH     |                        |               | glibc: uncontrolled recursion in        |
|               |                  |          |                        |               | function check_dst_limits_calc_pos_1    |
|               |                  |          |                        |               | in posix/regexec.c                      |
|               |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2018-20796   |
+               +------------------+          +                        +---------------+-----------------------------------------+
|               | CVE-2019-1010023 |          |                        |               | glibc: running ldd on malicious ELF     |
|               |                  |          |                        |               | leads to code execution because of...   |
|               |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2019-1010023 |
+               +------------------+          +                        +---------------+-----------------------------------------+
|               | CVE-2019-9192    |          |                        |               | glibc: uncontrolled recursion in        |
|               |                  |          |                        |               | function check_dst_limits_calc_pos_1    |
|               |                  |          |                        |               | in posix/regexec.c                      |
|               |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2019-9192    |
+               +------------------+          +                        +---------------+-----------------------------------------+
|               | CVE-2020-1751    |          |                        |               | glibc: array overflow in                |
|               |                  |          |                        |               | backtrace functions for powerpc         |
|               |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2020-1751    |
+               +------------------+----------+                        +---------------+-----------------------------------------+
|               | CVE-2010-4756    | MEDIUM   |                        |               | glibc: glob implementation              |
|               |                  |          |                        |               | can cause excessive CPU and             |
|               |                  |          |                        |               | memory consumption due to...            |
|               |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2010-4756    |
+               +------------------+          +                        +---------------+-----------------------------------------+
|               | CVE-2019-1010024 |          |                        |               | glibc: ASLR bypass using                |
|               |                  |          |                        |               | cache of thread stack and heap          |
|               |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2019-1010024 |
+               +------------------+          +                        +---------------+-----------------------------------------+
|               | CVE-2019-1010025 |          |                        |               | glibc: information disclosure of heap   |
|               |                  |          |                        |               | addresses of pthread_created thread     |
|               |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2019-1010025 |
+---------------+------------------+----------+                        +---------------+-----------------------------------------+
| libc6         | CVE-2019-1010022 | CRITICAL |                        |               | glibc: stack guard protection bypass    |
|               |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2019-1010022 |
+               +------------------+----------+                        +---------------+-----------------------------------------+
|               | CVE-2018-20796   | HIGH     |                        |               | glibc: uncontrolled recursion in        |
|               |                  |          |                        |               | function check_dst_limits_calc_pos_1    |
|               |                  |          |                        |               | in posix/regexec.c                      |
|               |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2018-20796   |
+               +------------------+          +                        +---------------+-----------------------------------------+
|               | CVE-2019-1010023 |          |                        |               | glibc: running ldd on malicious ELF     |
|               |                  |          |                        |               | leads to code execution because of...   |
|               |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2019-1010023 |
+               +------------------+          +                        +---------------+-----------------------------------------+
|               | CVE-2019-9192    |          |                        |               | glibc: uncontrolled recursion in        |
|               |                  |          |                        |               | function check_dst_limits_calc_pos_1    |
|               |                  |          |                        |               | in posix/regexec.c                      |
|               |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2019-9192    |
+               +------------------+          +                        +---------------+-----------------------------------------+
|               | CVE-2020-1751    |          |                        |               | glibc: array overflow in                |
|               |                  |          |                        |               | backtrace functions for powerpc         |
|               |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2020-1751    |
+               +------------------+----------+                        +---------------+-----------------------------------------+
|               | CVE-2010-4756    | MEDIUM   |                        |               | glibc: glob implementation              |
|               |                  |          |                        |               | can cause excessive CPU and             |
|               |                  |          |                        |               | memory consumption due to...            |
|               |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2010-4756    |
+               +------------------+          +                        +---------------+-----------------------------------------+
|               | CVE-2019-1010024 |          |                        |               | glibc: ASLR bypass using                |
|               |                  |          |                        |               | cache of thread stack and heap          |
|               |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2019-1010024 |
+               +------------------+          +                        +---------------+-----------------------------------------+
|               | CVE-2019-1010025 |          |                        |               | glibc: information disclosure of heap   |
|               |                  |          |                        |               | addresses of pthread_created thread     |
|               |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2019-1010025 |
+---------------+------------------+----------+------------------------+---------------+-----------------------------------------+
| libcom-err2   | CVE-2022-1304    | HIGH     | 1.44.5-1+deb10u3       |               | e2fsprogs: out-of-bounds                |
|               |                  |          |                        |               | read/write via crafted filesystem       |
|               |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2022-1304    |
+---------------+------------------+----------+------------------------+---------------+-----------------------------------------+
| libdb5.3      | CVE-2019-8457    | CRITICAL | 5.3.28+dfsg1-0.5       |               | sqlite: heap out-of-bound               |
|               |                  |          |                        |               | read in function rtreenode()            |
|               |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2019-8457    |
+---------------+------------------+----------+------------------------+---------------+-----------------------------------------+
| libext2fs2    | CVE-2022-1304    | HIGH     | 1.44.5-1+deb10u3       |               | e2fsprogs: out-of-bounds                |
|               |                  |          |                        |               | read/write via crafted filesystem       |
|               |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2022-1304    |
+---------------+------------------+----------+------------------------+---------------+-----------------------------------------+
| libfdisk1     | CVE-2021-37600   | MEDIUM   | 2.33.1-0.1             |               | util-linux: integer overflow            |
|               |                  |          |                        |               | can lead to buffer overflow             |
|               |                  |          |                        |               | in get_sem_elements() in                |
|               |                  |          |                        |               | sys-utils/ipcutils.c...                 |
|               |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2021-37600   |
+               +------------------+          +                        +---------------+-----------------------------------------+
|               | CVE-2022-0563    |          |                        |               | util-linux: partial disclosure          |
|               |                  |          |                        |               | of arbitrary files in chfn              |
|               |                  |          |                        |               | and chsh when compiled...               |
|               |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2022-0563    |
+---------------+------------------+----------+------------------------+---------------+-----------------------------------------+
| libgcc1       | CVE-2018-12886   | HIGH     | 8.3.0-6                |               | gcc: spilling of stack                  |
|               |                  |          |                        |               | protection address in cfgexpand.c       |
|               |                  |          |                        |               | and function.c leads to...              |
|               |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2018-12886   |
+               +------------------+          +                        +---------------+-----------------------------------------+
|               | CVE-2019-15847   |          |                        |               | gcc: POWER9 "DARN" RNG intrinsic        |
|               |                  |          |                        |               | produces repeated output                |
|               |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2019-15847   |
+---------------+------------------+          +------------------------+---------------+-----------------------------------------+
| libgcrypt20   | CVE-2018-6829    |          | 1.8.4-5+deb10u1        |               | libgcrypt: ElGamal implementation       |
|               |                  |          |                        |               | doesn't have semantic security due      |
|               |                  |          |                        |               | to incorrectly encoded plaintexts...    |
|               |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2018-6829    |
+               +------------------+          +                        +---------------+-----------------------------------------+
|               | CVE-2021-33560   |          |                        |               | libgcrypt: mishandles ElGamal           |
|               |                  |          |                        |               | encryption because it lacks             |
|               |                  |          |                        |               | exponent blinding to address a...       |
|               |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2021-33560   |
+               +------------------+----------+                        +---------------+-----------------------------------------+
|               | CVE-2019-13627   | MEDIUM   |                        |               | libgcrypt: ECDSA timing attack          |
|               |                  |          |                        |               | allowing private key leak               |
|               |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2019-13627   |
+---------------+------------------+          +------------------------+---------------+-----------------------------------------+
| libgnutls30   | CVE-2011-3389    |          | 3.6.7-4+deb10u10       |               | HTTPS: block-wise chosen-plaintext      |
|               |                  |          |                        |               | attack against SSL/TLS (BEAST)          |
|               |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2011-3389    |
+---------------+------------------+----------+------------------------+---------------+-----------------------------------------+
| libidn2-0     | CVE-2019-12290   | HIGH     | 2.0.5-1+deb10u1        |               | GNU libidn2 before 2.2.0                |
|               |                  |          |                        |               | fails to perform the roundtrip          |
|               |                  |          |                        |               | checks specified in...                  |
|               |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2019-12290   |
+---------------+------------------+          +------------------------+---------------+-----------------------------------------+
| liblz4-1      | CVE-2019-17543   |          | 1.8.3-1+deb10u1        |               | lz4: heap-based buffer                  |
|               |                  |          |                        |               | overflow in LZ4_write32                 |
|               |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2019-17543   |
+---------------+------------------+----------+------------------------+---------------+-----------------------------------------+
| libmount1     | CVE-2021-37600   | MEDIUM   | 2.33.1-0.1             |               | util-linux: integer overflow            |
|               |                  |          |                        |               | can lead to buffer overflow             |
|               |                  |          |                        |               | in get_sem_elements() in                |
|               |                  |          |                        |               | sys-utils/ipcutils.c...                 |
|               |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2021-37600   |
+               +------------------+          +                        +---------------+-----------------------------------------+
|               | CVE-2022-0563    |          |                        |               | util-linux: partial disclosure          |
|               |                  |          |                        |               | of arbitrary files in chfn              |
|               |                  |          |                        |               | and chsh when compiled...               |
|               |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2022-0563    |
+---------------+------------------+----------+------------------------+---------------+-----------------------------------------+
| libncursesw6  | CVE-2021-39537   | HIGH     | 6.1+20181013-2+deb10u4 |               | ncurses: heap-based buffer overflow     |
|               |                  |          |                        |               | in _nc_captoinfo() in captoinfo.c       |
|               |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2021-39537   |
+---------------+------------------+          +------------------------+---------------+-----------------------------------------+
| libpcre3      | CVE-2017-11164   |          | 2:8.39-12              |               | pcre: OP_KETRMAX feature in the         |
|               |                  |          |                        |               | match function in pcre_exec.c           |
|               |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2017-11164   |
+               +------------------+          +                        +---------------+-----------------------------------------+
|               | CVE-2017-7245    |          |                        |               | pcre: stack-based buffer overflow       |
|               |                  |          |                        |               | write in pcre32_copy_substring          |
|               |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2017-7245    |
+               +------------------+          +                        +---------------+-----------------------------------------+
|               | CVE-2017-7246    |          |                        |               | pcre: stack-based buffer overflow       |
|               |                  |          |                        |               | write in pcre32_copy_substring          |
|               |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2017-7246    |
+               +------------------+          +                        +---------------+-----------------------------------------+
|               | CVE-2019-20838   |          |                        |               | pcre: Buffer over-read in JIT           |
|               |                  |          |                        |               | when UTF is disabled and \X or...       |
|               |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2019-20838   |
+               +------------------+----------+                        +---------------+-----------------------------------------+
|               | CVE-2017-16231   | MEDIUM   |                        |               | pcre: self-recursive call               |
|               |                  |          |                        |               | in match() in pcre_exec.c               |
|               |                  |          |                        |               | leads to denial of service...           |
|               |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2017-16231   |
+               +------------------+          +                        +---------------+-----------------------------------------+
|               | CVE-2020-14155   |          |                        |               | pcre: Integer overflow when             |
|               |                  |          |                        |               | parsing callout numeric arguments       |
|               |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2020-14155   |
+---------------+------------------+----------+------------------------+---------------+-----------------------------------------+
| libseccomp2   | CVE-2019-9893    | CRITICAL | 2.3.3-4                |               | libseccomp: incorrect generation        |
|               |                  |          |                        |               | of syscall filters in libseccomp        |
|               |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2019-9893    |
+---------------+------------------+----------+------------------------+---------------+-----------------------------------------+
| libsepol1     | CVE-2021-36084   | LOW      | 2.8-1                  |               | libsepol: use-after-free in             |
|               |                  |          |                        |               | __cil_verify_classperms()               |
|               |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2021-36084   |
+               +------------------+          +                        +---------------+-----------------------------------------+
|               | CVE-2021-36085   |          |                        |               | libsepol: use-after-free in             |
|               |                  |          |                        |               | __cil_verify_classperms()               |
|               |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2021-36085   |
+               +------------------+          +                        +---------------+-----------------------------------------+
|               | CVE-2021-36086   |          |                        |               | libsepol: use-after-free in             |
|               |                  |          |                        |               | cil_reset_classpermission()             |
|               |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2021-36086   |
+               +------------------+          +                        +---------------+-----------------------------------------+
|               | CVE-2021-36087   |          |                        |               | libsepol: heap-based buffer             |
|               |                  |          |                        |               | overflow in ebitmap_match_any()         |
|               |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2021-36087   |
+---------------+------------------+----------+------------------------+---------------+-----------------------------------------+
| libsmartcols1 | CVE-2021-37600   | MEDIUM   | 2.33.1-0.1             |               | util-linux: integer overflow            |
|               |                  |          |                        |               | can lead to buffer overflow             |
|               |                  |          |                        |               | in get_sem_elements() in                |
|               |                  |          |                        |               | sys-utils/ipcutils.c...                 |
|               |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2021-37600   |
+               +------------------+          +                        +---------------+-----------------------------------------+
|               | CVE-2022-0563    |          |                        |               | util-linux: partial disclosure          |
|               |                  |          |                        |               | of arbitrary files in chfn              |
|               |                  |          |                        |               | and chsh when compiled...               |
|               |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2022-0563    |
+---------------+------------------+----------+------------------------+---------------+-----------------------------------------+
| libss2        | CVE-2022-1304    | HIGH     | 1.44.5-1+deb10u3       |               | e2fsprogs: out-of-bounds                |
|               |                  |          |                        |               | read/write via crafted filesystem       |
|               |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2022-1304    |
+---------------+------------------+          +------------------------+---------------+-----------------------------------------+
| libstdc++6    | CVE-2018-12886   |          | 8.3.0-6                |               | gcc: spilling of stack                  |
|               |                  |          |                        |               | protection address in cfgexpand.c       |
|               |                  |          |                        |               | and function.c leads to...              |
|               |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2018-12886   |
+               +------------------+          +                        +---------------+-----------------------------------------+
|               | CVE-2019-15847   |          |                        |               | gcc: POWER9 "DARN" RNG intrinsic        |
|               |                  |          |                        |               | produces repeated output                |
|               |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2019-15847   |
+---------------+------------------+          +------------------------+---------------+-----------------------------------------+
| libsystemd0   | CVE-2019-3843    |          | 241-7~deb10u10         |               | systemd: services with DynamicUser      |
|               |                  |          |                        |               | can create SUID/SGID binaries           |
|               |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2019-3843    |
+               +------------------+          +                        +---------------+-----------------------------------------+
|               | CVE-2019-3844    |          |                        |               | systemd: services with DynamicUser      |
|               |                  |          |                        |               | can get new privileges and              |
|               |                  |          |                        |               | create SGID binaries...                 |
|               |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2019-3844    |
+               +------------------+----------+                        +---------------+-----------------------------------------+
|               | CVE-2020-13529   | MEDIUM   |                        |               | systemd: DHCP FORCERENEW                |
|               |                  |          |                        |               | authentication not implemented          |
|               |                  |          |                        |               | can cause a system running the...       |
|               |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2020-13529   |
+               +------------------+          +                        +---------------+-----------------------------------------+
|               | CVE-2021-3997    |          |                        |               | systemd: Uncontrolled recursion in      |
|               |                  |          |                        |               | systemd-tmpfiles when removing files    |
|               |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2021-3997    |
+               +------------------+          +                        +---------------+-----------------------------------------+
|               | CVE-2022-3821    |          |                        |               | systemd: buffer overrun in              |
|               |                  |          |                        |               | format_timespan() function              |
|               |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2022-3821    |
+               +------------------+          +                        +---------------+-----------------------------------------+
|               | CVE-2022-4415    |          |                        |               | systemd: local information leak due     |
|               |                  |          |                        |               | to systemd-coredump not respecting      |
|               |                  |          |                        |               | fs.suid_dumpable kernel setting...      |
|               |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2022-4415    |
+               +------------------+----------+                        +---------------+-----------------------------------------+
|               | CVE-2013-4392    | LOW      |                        |               | systemd: TOCTOU race condition          |
|               |                  |          |                        |               | when updating file permissions          |
|               |                  |          |                        |               | and SELinux security contexts...        |
|               |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2013-4392    |
+               +------------------+          +                        +---------------+-----------------------------------------+
|               | CVE-2019-20386   |          |                        |               | systemd: memory leak in button_open()   |
|               |                  |          |                        |               | in login/logind-button.c when           |
|               |                  |          |                        |               | udev events are received...             |
|               |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2019-20386   |
+---------------+------------------+----------+------------------------+---------------+-----------------------------------------+
| libtasn1-6    | CVE-2018-1000654 | MEDIUM   | 4.13-3+deb10u1         |               | libtasn1: Infinite loop in              |
|               |                  |          |                        |               | _asn1_expand_object_id(ptree)           |
|               |                  |          |                        |               | leads to memory exhaustion              |
|               |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2018-1000654 |
+---------------+------------------+----------+------------------------+---------------+-----------------------------------------+
| libtinfo6     | CVE-2021-39537   | HIGH     | 6.1+20181013-2+deb10u4 |               | ncurses: heap-based buffer overflow     |
|               |                  |          |                        |               | in _nc_captoinfo() in captoinfo.c       |
|               |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2021-39537   |
+---------------+------------------+          +------------------------+---------------+-----------------------------------------+
| libudev1      | CVE-2019-3843    |          | 241-7~deb10u10         |               | systemd: services with DynamicUser      |
|               |                  |          |                        |               | can create SUID/SGID binaries           |
|               |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2019-3843    |
+               +------------------+          +                        +---------------+-----------------------------------------+
|               | CVE-2019-3844    |          |                        |               | systemd: services with DynamicUser      |
|               |                  |          |                        |               | can get new privileges and              |
|               |                  |          |                        |               | create SGID binaries...                 |
|               |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2019-3844    |
+               +------------------+----------+                        +---------------+-----------------------------------------+
|               | CVE-2020-13529   | MEDIUM   |                        |               | systemd: DHCP FORCERENEW                |
|               |                  |          |                        |               | authentication not implemented          |
|               |                  |          |                        |               | can cause a system running the...       |
|               |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2020-13529   |
+               +------------------+          +                        +---------------+-----------------------------------------+
|               | CVE-2021-3997    |          |                        |               | systemd: Uncontrolled recursion in      |
|               |                  |          |                        |               | systemd-tmpfiles when removing files    |
|               |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2021-3997    |
+               +------------------+          +                        +---------------+-----------------------------------------+
|               | CVE-2022-3821    |          |                        |               | systemd: buffer overrun in              |
|               |                  |          |                        |               | format_timespan() function              |
|               |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2022-3821    |
+               +------------------+          +                        +---------------+-----------------------------------------+
|               | CVE-2022-4415    |          |                        |               | systemd: local information leak due     |
|               |                  |          |                        |               | to systemd-coredump not respecting      |
|               |                  |          |                        |               | fs.suid_dumpable kernel setting...      |
|               |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2022-4415    |
+               +------------------+----------+                        +---------------+-----------------------------------------+
|               | CVE-2013-4392    | LOW      |                        |               | systemd: TOCTOU race condition          |
|               |                  |          |                        |               | when updating file permissions          |
|               |                  |          |                        |               | and SELinux security contexts...        |
|               |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2013-4392    |
+               +------------------+          +                        +---------------+-----------------------------------------+
|               | CVE-2019-20386   |          |                        |               | systemd: memory leak in button_open()   |
|               |                  |          |                        |               | in login/logind-button.c when           |
|               |                  |          |                        |               | udev events are received...             |
|               |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2019-20386   |
+---------------+------------------+----------+------------------------+---------------+-----------------------------------------+
| libuuid1      | CVE-2021-37600   | MEDIUM   | 2.33.1-0.1             |               | util-linux: integer overflow            |
|               |                  |          |                        |               | can lead to buffer overflow             |
|               |                  |          |                        |               | in get_sem_elements() in                |
|               |                  |          |                        |               | sys-utils/ipcutils.c...                 |
|               |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2021-37600   |
+               +------------------+          +                        +---------------+-----------------------------------------+
|               | CVE-2022-0563    |          |                        |               | util-linux: partial disclosure          |
|               |                  |          |                        |               | of arbitrary files in chfn              |
|               |                  |          |                        |               | and chsh when compiled...               |
|               |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2022-0563    |
+---------------+------------------+----------+------------------------+---------------+-----------------------------------------+
| login         | CVE-2019-19882   | HIGH     | 1:4.5-1.1              |               | shadow-utils: local users can           |
|               |                  |          |                        |               | obtain root access because setuid       |
|               |                  |          |                        |               | programs are misconfigured...           |
|               |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2019-19882   |
+               +------------------+----------+                        +---------------+-----------------------------------------+
|               | CVE-2007-5686    | MEDIUM   |                        |               | initscripts in rPath Linux 1            |
|               |                  |          |                        |               | sets insecure permissions for           |
|               |                  |          |                        |               | the /var/log/btmp file,...              |
|               |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2007-5686    |
+               +------------------+          +                        +---------------+-----------------------------------------+
|               | CVE-2013-4235    |          |                        |               | shadow-utils: TOCTOU race               |
|               |                  |          |                        |               | conditions by copying and               |
|               |                  |          |                        |               | removing directory trees                |
|               |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2013-4235    |
+               +------------------+          +                        +---------------+-----------------------------------------+
|               | CVE-2018-7169    |          |                        |               | shadow-utils: newgidmap                 |
|               |                  |          |                        |               | allows unprivileged user to             |
|               |                  |          |                        |               | drop supplementary groups               |
|               |                  |          |                        |               | potentially allowing privilege...       |
|               |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2018-7169    |
+               +------------------+----------+                        +---------------+-----------------------------------------+
|               | CVE-2023-0634    | UNKNOWN  |                        |               | An uncontrolled process                 |
|               |                  |          |                        |               | operation was found in the              |
|               |                  |          |                        |               | newgrp command provided by...           |
|               |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2023-0634    |
+---------------+------------------+----------+------------------------+---------------+-----------------------------------------+
| mount         | CVE-2021-37600   | MEDIUM   | 2.33.1-0.1             |               | util-linux: integer overflow            |
|               |                  |          |                        |               | can lead to buffer overflow             |
|               |                  |          |                        |               | in get_sem_elements() in                |
|               |                  |          |                        |               | sys-utils/ipcutils.c...                 |
|               |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2021-37600   |
+               +------------------+          +                        +---------------+-----------------------------------------+
|               | CVE-2022-0563    |          |                        |               | util-linux: partial disclosure          |
|               |                  |          |                        |               | of arbitrary files in chfn              |
|               |                  |          |                        |               | and chsh when compiled...               |
|               |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2022-0563    |
+---------------+------------------+----------+------------------------+---------------+-----------------------------------------+
| ncurses-base  | CVE-2021-39537   | HIGH     | 6.1+20181013-2+deb10u4 |               | ncurses: heap-based buffer overflow     |
|               |                  |          |                        |               | in _nc_captoinfo() in captoinfo.c       |
|               |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2021-39537   |
+---------------+                  +          +                        +---------------+                                         +
| ncurses-bin   |                  |          |                        |               |                                         |
|               |                  |          |                        |               |                                         |
|               |                  |          |                        |               |                                         |
+---------------+------------------+          +------------------------+---------------+-----------------------------------------+
| passwd        | CVE-2019-19882   |          | 1:4.5-1.1              |               | shadow-utils: local users can           |
|               |                  |          |                        |               | obtain root access because setuid       |
|               |                  |          |                        |               | programs are misconfigured...           |
|               |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2019-19882   |
+               +------------------+----------+                        +---------------+-----------------------------------------+
|               | CVE-2007-5686    | MEDIUM   |                        |               | initscripts in rPath Linux 1            |
|               |                  |          |                        |               | sets insecure permissions for           |
|               |                  |          |                        |               | the /var/log/btmp file,...              |
|               |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2007-5686    |
+               +------------------+          +                        +---------------+-----------------------------------------+
|               | CVE-2013-4235    |          |                        |               | shadow-utils: TOCTOU race               |
|               |                  |          |                        |               | conditions by copying and               |
|               |                  |          |                        |               | removing directory trees                |
|               |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2013-4235    |
+               +------------------+          +                        +---------------+-----------------------------------------+
|               | CVE-2018-7169    |          |                        |               | shadow-utils: newgidmap                 |
|               |                  |          |                        |               | allows unprivileged user to             |
|               |                  |          |                        |               | drop supplementary groups               |
|               |                  |          |                        |               | potentially allowing privilege...       |
|               |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2018-7169    |
+               +------------------+----------+                        +---------------+-----------------------------------------+
|               | CVE-2023-0634    | UNKNOWN  |                        |               | An uncontrolled process                 |
|               |                  |          |                        |               | operation was found in the              |
|               |                  |          |                        |               | newgrp command provided by...           |
|               |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2023-0634    |
+---------------+------------------+----------+------------------------+---------------+-----------------------------------------+
| perl-base     | CVE-2011-4116    | HIGH     | 5.28.1-6+deb10u1       |               | perl: File::Temp insecure               |
|               |                  |          |                        |               | temporary file handling                 |
|               |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2011-4116    |
+               +------------------+          +                        +---------------+-----------------------------------------+
|               | CVE-2020-16156   |          |                        |               | perl-CPAN: Bypass of verification       |
|               |                  |          |                        |               | of signatures in CHECKSUMS files        |
|               |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2020-16156   |
+---------------+------------------+          +------------------------+---------------+-----------------------------------------+
| tar           | CVE-2005-2541    |          | 1.30+dfsg-6            |               | tar: does not properly warn the user    |
|               |                  |          |                        |               | when extracting setuid or setgid...     |
|               |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2005-2541    |
+               +------------------+          +                        +---------------+-----------------------------------------+
|               | CVE-2019-9923    |          |                        |               | tar: null-pointer dereference           |
|               |                  |          |                        |               | in pax_decode_header in sparse.c        |
|               |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2019-9923    |
+               +------------------+          +                        +---------------+-----------------------------------------+
|               | CVE-2022-48303   |          |                        |               | tar: a heap buffer overflow             |
|               |                  |          |                        |               | at from_header() in list.c              |
|               |                  |          |                        |               | via specially crafter...                |
|               |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2022-48303   |
+               +------------------+----------+                        +---------------+-----------------------------------------+
|               | CVE-2021-20193   | MEDIUM   |                        |               | tar: Memory leak in                     |
|               |                  |          |                        |               | read_header() in list.c                 |
|               |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2021-20193   |
+---------------+------------------+          +------------------------+---------------+-----------------------------------------+
| util-linux    | CVE-2021-37600   |          | 2.33.1-0.1             |               | util-linux: integer overflow            |
|               |                  |          |                        |               | can lead to buffer overflow             |
|               |                  |          |                        |               | in get_sem_elements() in                |
|               |                  |          |                        |               | sys-utils/ipcutils.c...                 |
|               |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2021-37600   |
+               +------------------+          +                        +---------------+-----------------------------------------+
|               | CVE-2022-0563    |          |                        |               | util-linux: partial disclosure          |
|               |                  |          |                        |               | of arbitrary files in chfn              |
|               |                  |          |                        |               | and chsh when compiled...               |
|               |                  |          |                        |               | -->avd.aquasec.com/nvd/cve-2022-0563    |
+---------------+------------------+----------+------------------------+---------------+-----------------------------------------+
```

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