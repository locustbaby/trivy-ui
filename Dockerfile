ARG GOLANG_VERSION=1.25-bookworm
ARG VERSION

FROM golang:${GOLANG_VERSION} AS build
WORKDIR /app
RUN apt update && apt install -y curl git \
    && curl -fsSL https://deb.nodesource.com/setup_24.x | bash - \
    && apt install -y nodejs \
    && rm -rf /var/lib/apt/lists/*

COPY . /app/

WORKDIR /app/go-server
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o go-server
RUN mkdir -p /tmp/trivy-ui-data

WORKDIR /app/trivy-dashboard
RUN npm ci && npm run build


FROM gcr.io/distroless/static-debian12:nonroot
WORKDIR /app
ARG VERSION
ENV VERSION=${VERSION}
ENV DATA_PATH=/tmp/trivy-ui-data
COPY --from=build --chown=nonroot:nonroot /app/go-server/go-server /app/go-server
COPY --from=build --chown=nonroot:nonroot /app/trivy-dashboard/dist /app/trivy-dashboard/dist
COPY --from=build --chown=nonroot:nonroot /app/VERSION /app/VERSION
COPY --from=build --chown=nonroot:nonroot /tmp/trivy-ui-data /tmp/trivy-ui-data

LABEL org.opencontainers.image.description="This image contains Trivy UI"
LABEL org.opencontainers.image.authors="https://github.com/locustbaby"
LABEL org.opencontainers.image.source="https://github.com/locustbaby/trivy-ui"
LABEL org.opencontainers.image.version="${VERSION}"

USER nonroot
CMD ["/app/go-server"]
EXPOSE 8080
