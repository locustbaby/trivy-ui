# syntax=docker/dockerfile:1

ARG GOLANG_VERSION=1.25-bookworm
ARG NODE_VERSION=24-bookworm-slim
ARG VERSION

FROM --platform=$BUILDPLATFORM node:${NODE_VERSION} AS frontend-build
WORKDIR /app/trivy-dashboard
COPY trivy-dashboard/package.json trivy-dashboard/package-lock.json ./
RUN --mount=type=cache,target=/root/.npm npm ci
COPY trivy-dashboard/ ./
RUN npm run build

FROM --platform=$BUILDPLATFORM golang:${GOLANG_VERSION} AS server-build
ARG TARGETOS TARGETARCH
WORKDIR /app/go-server
COPY go-server/go.mod go-server/go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY go-server/ ./
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -ldflags="-s -w" -o go-server
RUN mkdir -p /tmp/trivy-ui-data


FROM gcr.io/distroless/static-debian12:nonroot
WORKDIR /app
ARG VERSION
ENV VERSION=${VERSION}
ENV DATA_PATH=/tmp/trivy-ui-data
COPY --from=server-build --chown=nonroot:nonroot /app/go-server/go-server /app/go-server
COPY --from=frontend-build --chown=nonroot:nonroot /app/trivy-dashboard/dist /app/trivy-dashboard/dist
COPY --chown=nonroot:nonroot VERSION /app/VERSION
COPY --from=server-build --chown=nonroot:nonroot /tmp/trivy-ui-data /tmp/trivy-ui-data

LABEL org.opencontainers.image.description="This image contains Trivy UI"
LABEL org.opencontainers.image.authors="https://github.com/locustbaby"
LABEL org.opencontainers.image.source="https://github.com/locustbaby/trivy-ui"
LABEL org.opencontainers.image.version="${VERSION}"

USER nonroot
CMD ["/app/go-server"]
EXPOSE 8080
