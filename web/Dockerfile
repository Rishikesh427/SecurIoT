FROM node:22-alpine AS development
WORKDIR /app
COPY web/package*.json ./
RUN npm ci
COPY web/ ./
COPY contract/fixtures.json /contract/fixtures.json
ARG VITE_API_URL=/api
ARG VITE_MOCK_MODE=false
ENV VITE_API_URL=$VITE_API_URL VITE_MOCK_MODE=$VITE_MOCK_MODE
EXPOSE 5173
CMD ["npm", "run", "dev", "--", "--host", "0.0.0.0"]

FROM development AS build
RUN npm run build

FROM caddy:2.10.0-alpine AS production
COPY --from=build /app/dist /srv
