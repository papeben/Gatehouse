FROM alpine:3.17.2
RUN apk update && \
    apk upgrade
WORKDIR /app
COPY Gatehouse .
COPY assets .
CMD ["./Gatehouse"]

