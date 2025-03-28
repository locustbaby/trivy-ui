ARG NODE_VERSION=23.10.0-alpine3.21
ARG GOLANG_VERSION=1.24.1-bullseye

FROM golang:${GOLANG_VERSION} AS build
WORKDIR /app
RUN apt update && apt install -y curl git \
    && curl -fsSL https://deb.nodesource.com/setup_23.x | bash - \
    && apt install -y nodejs \
    && npm install -g npm@latest \
    && rm -rf /var/lib/apt/lists/*
RUN git clone "https://github.com/locustbaby/trivy-ui.git"
RUN cd trivy-ui/go-server && go build -o go-server
RUN cd trivy-ui/trivy-dashboard && npm install && npm run build


FROM debian:bullseye-slim
WORKDIR /app
COPY --from=build /app/trivy-ui/go-server/go-server /app/go-server
COPY --from=build /app/trivy-ui/trivy-dashboard/dist /app/trivy-dashboard/dist
RUN apt update && apt install -y ca-certificates && rm -rf /var/lib/apt/lists/*

LABEL org.opencontainers.image.description "This image contains Trivy UI"
LABEL org.opencontainers.image.authors "https://github.com/locustbaby"
LABEL org.opencontainers.image.source "https://github.com/locustbaby/trivy-ui"

CMD ["/app/go-server"]
EXPOSE 8080
