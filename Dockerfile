ARG NODE_VERSION=23.10.0-alpine3.21
ARG GOLANG_VERSION=1.24.1-bullseye

FROM golang:${GOLANG_VERSION} AS build
WORKDIR /app
RUN apt update && apt install -y curl \
    && curl -fsSL https://deb.nodesource.com/setup_23.x | bash - \
    && apt install -y nodejs \
    && npm install -g npm@latest \
    && rm -rf /var/lib/apt/lists/*
COPY . .
RUN cd go-server && go build
RUN cd trivy-dashboard && npm install && npm run build


FROM debian:bullseye-slim
WORKDIR /app
COPY --from=build /app/go-server/go-server /app/go-server
COPY --from=build /app/trivy-dashboard/build /app/trivy-dashboard/build
RUN apt update && apt install -y ca-certificates && rm -rf /var/lib/apt/lists/*

LABEL org.opencontainers.image.description "This image contains Backend Trivy UI (https://github.com/locustbaby/trivy-ui)"
LABEL org.opencontainers.image.url "https://github.com/llocustbaby/trivy-ui"
LABEL org.opencontainers.image.documentation "https://github.com/locustbaby/trivy-ui/blob/main/README.md"
LABEL org.opencontainers.image.authors "https://github.com/locustbaby"
LABEL org.opencontainers.image.source "https://github.com/locustbaby/trivy-ui"

CMD ["/app/go-server"]
EXPOSE 8080
