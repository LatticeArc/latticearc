# OSS-Fuzz Dockerfile for LatticeArc
# This file is used when LatticeArc is integrated into Google's OSS-Fuzz program
# See: https://google.github.io/oss-fuzz/

FROM gcr.io/oss-fuzz-base/base-builder-rust

# Clone the repository
RUN git clone --depth 1 https://github.com/anthropics/latticearc $SRC/latticearc

# Set working directory
WORKDIR $SRC/latticearc

# Copy build script
COPY build.sh $SRC/
