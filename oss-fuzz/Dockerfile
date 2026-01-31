# OSS-Fuzz Dockerfile for LatticeArc
# This file is used when LatticeArc is integrated into Google's OSS-Fuzz program
# See: https://google.github.io/oss-fuzz/

FROM gcr.io/oss-fuzz-base/base-builder-rust@sha256:ab364e12cafa40f9ee70ab7894ebbf44fa11988b5b697d73de1695b94ddfba9e

# Clone the repository
RUN git clone --depth 1 https://github.com/LatticeArc/latticearc $SRC/latticearc

# Set working directory
WORKDIR $SRC/latticearc

# Copy build script
COPY build.sh $SRC/
