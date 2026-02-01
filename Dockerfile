ARG NODE_VERSION=23.10.0-alpine3.21
ARG GOLANG_VERSION=1.24.4-bookworm
ARG VERSION

FROM golang:${GOLANG_VERSION} AS build
WORKDIR /app
RUN apt update && apt install -y curl git \
    && curl -fsSL https://deb.nodesource.com/setup_23.x | bash - \
    && apt install -y nodejs \
    && npm install -g npm@latest \
    && rm -rf /var/lib/apt/lists/*

# Copy source code from build context instead of git clone
COPY . /app/

# Build Go server
WORKDIR /app/go-server
RUN go build -o go-server

# Build frontend
WORKDIR /app/trivy-dashboard
RUN npm install && npm run build


FROM debian:bookworm-slim
WORKDIR /app
ARG VERSION
ENV VERSION=${VERSION}
COPY --from=build /app/go-server/go-server /app/go-server
COPY --from=build /app/trivy-dashboard/dist /app/trivy-dashboard/dist
COPY --from=build /app/VERSION /app/VERSION
RUN apt update && apt install -y ca-certificates && rm -rf /var/lib/apt/lists/*

LABEL org.opencontainers.image.description "This image contains Trivy UI"
LABEL org.opencontainers.image.authors "https://github.com/locustbaby"
LABEL org.opencontainers.image.source "https://github.com/locustbaby/trivy-ui"
LABEL org.opencontainers.image.version "${VERSION}"
LABEL org.opencontainers.image.created "$(date -u +"%Y-%m-%dT%H:%M:%SZ")"

CMD ["/app/go-server"]
EXPOSE 8080
