# syntax=docker/dockerfile:1
FROM node:latest as builder
WORKDIR /app
COPY . .
RUN npm install && npm run build

FROM nginx:alpine
WORKDIR /usr/share/nginx/html
RUN rm -rf ./*
COPY --from=builder /app/build/ .
# EXPOSE 8080
ENTRYPOINT [ "nginx", "-g", "daemon off;" ]