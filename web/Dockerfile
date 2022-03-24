# syntax=docker/dockerfile:1
FROM node:latest as builder
WORKDIR /app
COPY . .
RUN npm install && npm run build

FROM nginx:alpine
WORKDIR /usr/share/nginx/html
RUN rm -rf ./*
COPY --from=builder /app/build/ .
ENTRYPOINT [ "nginx", "-g", "daemon off;" ]

# FROM python:3.8-slim-buster
# WORKDIR /app
# COPY requirement.txt requirement.txt
# RUN pip install -r requirement.txt
# COPY . .
# EXPOSE 8080
# # CMD [ "python", "-m" , "flask", "run", "--host=0.0.0.0"]
# CMD ["python", "server.py"]