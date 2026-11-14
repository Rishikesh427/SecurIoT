FROM node:22-alpine AS build
WORKDIR /app
COPY web/package*.json ./
RUN npm ci
COPY web/ ./
COPY contract/fixtures.json /contract/fixtures.json
ARG VITE_API_URL=/api
ARG VITE_MOCK_MODE=false
ENV VITE_API_URL=$VITE_API_URL VITE_MOCK_MODE=$VITE_MOCK_MODE
RUN npm run build

FROM caddy:2.10.0-alpine
COPY --from=build /app/dist /srv
