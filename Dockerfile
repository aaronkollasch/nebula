#syntax=docker/dockerfile:1.2

#############      builder       #############
FROM golang:1.16-alpine AS builder

WORKDIR /go/src/github.com/slackhq/nebula

RUN apk add --no-cache bash git openssh make cmake gcc musl-dev

COPY . .

RUN make build/linux-amd64/nebula

# #############    docker-caps     #############
FROM scionproto/docker-caps as caps

# #############   nebula-alpine     #############
FROM alpine AS nebula-alpine

# COPY --from=builder /go/src/github.com/slackhq/nebula/build/linux-amd64/nebula /nebula
# # COPY --from=caps /bin/setcap /bin
# # RUN setcap cap_net_admin+ep /nebula && rm /bin/setcap
# RUN --mount=from=caps,dst=/caps ["/caps/bin/setcap","cap_net_admin+ep","/nebula"]

RUN \
  --mount=from=caps,src=/bin/,dst=/caps/ \
  --mount=from=builder,src=/go/src/github.com/slackhq/nebula/build/linux-amd64/,dst=/builder/ \
  ["sh", "-c", "cp /builder/nebula /nebula && /caps/setcap cap_net_admin+ep /nebula"]

WORKDIR /

ENTRYPOINT ["/nebula"]

# #############      nebula        #############
FROM scratch AS nebula-static

RUN \
  --mount=from=busybox:latest,dst=/usr/ \
  --mount=from=caps,src=/bin/,dst=/bin/ \
  --mount=from=builder,src=/go/src/github.com/slackhq/nebula/build/linux-amd64/,dst=/builder/ \
  ["busybox", "sh", "-c", "cp /builder/nebula /nebula && /bin/setcap cap_net_admin+ep /nebula"]

# # these lead to duplicate nebula copies in layers
# COPY --from=builder /go/src/github.com/slackhq/nebula/build/linux-amd64/nebula /nebula
# COPY --from=caps /bin/setcap /setcap
# RUN ["/setcap","cap_net_admin+ep","/nebula"]
# RUN --mount=from=caps,src=/bin/,dst=/bin/ ["/bin/setcap","cap_net_admin+ep","/nebula"]

WORKDIR /

ENTRYPOINT ["/nebula"]

