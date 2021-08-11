FROM golang:1.14-alpine
LABEL maintainer="Anish Shah"

RUN apk add --no-cache gcc libpcap-dev musl-dev
