FROM alpine:latest
RUN apk update && \
    apk upgrade
WORKDIR /app
COPY Gatehouse .
COPY assets ./assets
CMD ["./Gatehouse"]

