# SENTINEL X web — build stage
FROM node:20-alpine AS build
WORKDIR /app
COPY apps/web/package.json /app/package.json
COPY apps/web/package-lock.json* /app/
RUN npm install --no-audit --no-fund
COPY apps/web /app
RUN npm run build

# Serve stage
FROM nginx:1.27-alpine
COPY --from=build /app/dist /usr/share/nginx/html
COPY infrastructure/docker/nginx.conf /etc/nginx/conf.d/default.conf
EXPOSE 80
