# Copyright contributors to the IBM Security Verify Directory Operator project

# Build the manager binary
FROM golang:1.19 as builder
ARG TARGETOS
ARG TARGETARCH

WORKDIR /workspace
# Copy the Go Modules manifests
COPY go.mod go.mod
COPY go.sum go.sum
# cache deps before building and copying source so that we don't need to re-download as much
# and so that source changes don't invalidate our downloaded layer
RUN go mod download

# Copy the go source
COPY main.go main.go
COPY utils/ utils/
COPY api/ api/
COPY controllers/ controllers/

# Build
# the GOARCH has not a default value to allow the binary be built according to the host where the command
# was called. For example, if we call make docker-build in a local env which has the Apple Silicon M1 SO
# the docker BUILDPLATFORM arg will be linux/arm64 when for Apple x86 it will be linux/amd64. Therefore,
# by leaving it empty we can ensure that the container and binary shipped on it will have the same platform.
RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH} go build -a -o manager main.go

# In order to get this operator certified by RedHat it needs to be based on
# RedHat UBI.
FROM registry.access.redhat.com/ubi8/ubi-minimal:latest
WORKDIR /
COPY --from=builder /workspace/manager .
USER 65532:65532

### Required OpenShift Labels
LABEL name="IBM Security Verify Directory Operator" \
      vendor="IBM" \
      version="v--version--" \
      release="0" \
      summary="This operator can be used to scale an IBM Security Verify Directory server environment." \
      description="IBM Security Verify Directory is a scalable, standards-based identity directory that helps simplify identity and directory management. Verify Directory helps consolidate identity silos into a single identity source. Verify Directory is purpose-built to provide a directory foundation that can help provide a trusted identity data infrastructure that assists in enabling mission-critical security and authentication. It is designed to deliver a reliable, scalable, standards-based identity data platform that interoperates with a broad range of operating systems and applications. Verify Directory supports Lightweight Directory Access Protocol (LDAP) V3, offering a flexible and highly scalable LDAP infrastructure."

# Required Licenses
COPY licenses /licenses

ENTRYPOINT ["/manager"]
