FROM alpine:3.21 AS builder
WORKDIR /app
RUN wget https://github.com/andrew-d/static-binaries/raw/master/binaries/linux/x86_64/socat
RUN chmod +x ./socat
COPY ./chall chall
RUN chmod +x ./chall

FROM gcr.io/distroless/base-debian11
USER 65532
WORKDIR /app

COPY flag.txt flag.txt
COPY --from=builder /app/socat .
COPY --from=builder /app/chall .

EXPOSE 5000
CMD ["./socat", "tcp-l:5000,fork", "EXEC:\"./chall\""]
