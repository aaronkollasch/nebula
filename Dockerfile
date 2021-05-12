#############      builder       #############
FROM golang:1.16-alpine AS builder

WORKDIR /go/src/github.com/slackhq/nebula

RUN apk add --no-cache bash git openssh make cmake gcc musl-dev

COPY . .

#RUN make bin
RUN make build/linux-amd64/nebula

# #############      nebula        #############
FROM scratch AS nebula

#COPY --from=builder /go/src/github.com/slackhq/nebula/nebula /nebula
COPY --from=builder /go/src/github.com/slackhq/nebula/build/linux-amd64/nebula /nebula

WORKDIR /

ENTRYPOINT ["/nebula"]

