#------------------------build-------------------------
FROM --platform=$BUILDPLATFORM golang:1.21-alpine AS builder

WORKDIR /go/src/github.com/standchan/zlm_exporter/
ADD . /go/src/github.com/standchan/zlm_exporter/

ARG SHA1="[no-sha]"
ARG TAG="[no-tag]"
ARG TARGETOS
ARG TARGETARCH

# USER root
# RUN apk update && \
#     apk add --no-cache --no-progress ca-certificates git && \
#     update-ca-certificates
# GOOS=${TARGETOS} GOARCH=${TARGETARCH}
RUN BUILD_DATE=$(date +%F-%T) CGO_ENABLED=0  go build \
    -ldflags="-w -s" -o zlm_exporter .

# todo ssl/certs
#------------------------load-------------------------
FROM alpine:latest
RUN apk add --no-cache ca-certificates tzdata && \
    adduser -D -H -h /app appuser

WORKDIR /app
COPY --from=builder /go/src/github.com/standchan/zlm_exporter/zlm_exporter .

# Run as non-root user for secure environments
USER 59000:59000

EXPOSE 9101

ENTRYPOINT ["/app/zlm_exporter"]