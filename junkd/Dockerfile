FROM golang:1.24 AS builder

WORKDIR /junkd

# get dependencies
COPY go.mod go.sum ./
RUN go mod download

# copy source
COPY . .
# build
RUN go build -o bin/junkd -tags='netgo timetzdata' -trimpath -a -ldflags '-s -w'  ./

FROM debian:bookworm-slim

LABEL maintainer="The Sia Foundation <info@sia.tech>" \
    org.opencontainers.image.description.vendor="The Sia Foundation" \
    org.opencontainers.image.description="A test container for uploading random data to the Sia network" \
    org.opencontainers.image.source="https://github.com/SiaFoundation/indexd-utils" \
    org.opencontainers.image.licenses=MIT

# copy binary and certificates
COPY --from=builder /junkd/bin/junkd /usr/bin/junkd
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

ENTRYPOINT [ "junkd" ]
CMD [ "--help" ]
