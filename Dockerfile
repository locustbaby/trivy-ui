ARG NODE_VERSION=23.10.0-alpine3.21
ARG GOLANG_VERSION=1.25.7-bookworm
ARG VERSION

FROM golang:${GOLANG_VERSION} AS build
WORKDIR /app
RUN apt update && apt install -y curl git \
    && curl -fsSL https://deb.nodesource.com/setup_23.x | bash - \
    && apt install -y nodejs \
    && npm install -g npm@latest \
    && rm -rf /var/lib/apt/lists/*

COPY . /app/

WORKDIR /app/go-server
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o go-server

WORKDIR /app/trivy-dashboard
RUN npm install && npm run build


FROM gcr.io/distroless/static-debian12:nonroot
WORKDIR /app
ARG VERSION
ENV VERSION=${VERSION}
COPY --from=build --chown=nonroot:nonroot /app/go-server/go-server /app/go-server
COPY --from=build --chown=nonroot:nonroot /app/trivy-dashboard/dist /app/trivy-dashboard/dist
COPY --from=build --chown=nonroot:nonroot /app/VERSION /app/VERSION

LABEL org.opencontainers.image.description "This image contains Trivy UI"
LABEL org.opencontainers.image.authors "https://github.com/locustbaby"
LABEL org.opencontainers.image.source "https://github.com/locustbaby/trivy-ui"
LABEL org.opencontainers.image.version "${VERSION}"

USER nonroot
CMD ["/app/go-server"]
EXPOSE 8080
