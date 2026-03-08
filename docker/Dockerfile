#syntax=docker/dockerfile:1.2

# #############    docker-caps     #############
FROM debian:bookworm AS caps_build

RUN \
    apt-get update && apt-get install -y --no-install-recommends \
        gcc \
        git \
        libc6-dev \
        make \
    && rm -rf /var/lib/apt/lists/*

RUN cd /root && git clone git://git.kernel.org/pub/scm/libs/libcap/libcap.git

RUN cd /root/libcap && make

WORKDIR /

FROM scratch AS caps

COPY --from=caps_build /root/libcap/progs/capsh /bin/
COPY --from=caps_build /root/libcap/progs/getcap /bin/
COPY --from=caps_build /root/libcap/progs/setcap /bin/

CMD ["/bin/capsh", "--print"]

# #############      nebula        #############
FROM busybox:1.37 as busybox

FROM scratch

ARG TARGETOS TARGETARCH
COPY build/$TARGETOS-$TARGETARCH/nebula /nebula
COPY build/$TARGETOS-$TARGETARCH/nebula-cert /nebula-cert

VOLUME ["/config"]

RUN \
  --mount=from=busybox,source=/usr,target=/usr \
  --mount=from=busybox,source=/lib,target=/lib \
  --mount=from=busybox,source=/lib,target=/lib64 \
  --mount=from=busybox,source=/bin,target=/bin \
  --mount=from=caps,source=/bin,target=/caps \
  ["busybox", "sh", "-c", "/caps/setcap cap_net_admin+ep /nebula"]

ENTRYPOINT ["/nebula"]
# Allow users to override the args passed to nebula
CMD ["-config", "/config/config.yml"]
