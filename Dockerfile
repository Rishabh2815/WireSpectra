# Build the DPI CLI and its dependencies in a dedicated stage.
FROM ubuntu:24.04 AS build

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
    && apt-get install -y --no-install-recommends cmake g++ libssl-dev libpcap-dev pkg-config make \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY CMakeLists.txt ./
COPY include ./include
COPY src ./src
RUN cmake -S . -B build -DCMAKE_BUILD_TYPE=Release \
    && cmake --build build --config Release --parallel 2

# Runtime stage contains only the binary and shared runtime libraries.
FROM ubuntu:24.04 AS runtime

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
    && apt-get install -y --no-install-recommends libssl3 libpcap0.8 ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 --create-home --home-dir /home/wirespectra wirespectra

COPY --from=build /src/build/packet_analyzer /usr/local/bin/packet_analyzer
WORKDIR /data
USER 10001:10001
ENTRYPOINT ["/usr/local/bin/packet_analyzer"]
