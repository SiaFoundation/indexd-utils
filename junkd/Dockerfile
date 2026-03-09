FROM golang:1.26 AS builder

WORKDIR /junkd

# install git-lfs to support modules fetched via LFS
RUN apt-get update \
    && apt-get install -y --no-install-recommends git-lfs \
    && git lfs install

# setup auth for indexd package access
RUN mkdir -p ~/.ssh \
    && chmod 700 ~/.ssh \
    && ssh-keyscan github.com >> ~/.ssh/known_hosts \
    && chmod 644 ~/.ssh/known_hosts

COPY indexd_ed25519 /root/.ssh/id_ed25519
RUN chmod 600 ~/.ssh/id_ed25519
RUN git config --global url."git@github.com:".insteadOf "https://github.com/"
RUN git config --global url."ssh://git@github.com/".insteadOf "https://github.com/"

ENV GOPRIVATE=go.sia.tech/indexd 

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
