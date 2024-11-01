FROM golang:1.21-alpine AS builder

WORKDIR /app
COPY . .
RUN go mod download
RUN CGO_ENABLED=0 GOOS=linux go build -o zlm_exporter

FROM alpine:latest

WORKDIR /app
COPY --from=builder /app/zlm_exporter .

EXPOSE 9101

ENTRYPOINT ["/app/zlm_exporter"]
