FROM docker:29-dind
RUN --mount=type=secret,id=extra_ca if [ -s /run/secrets/extra_ca ]; then cat /run/secrets/extra_ca >> /etc/ssl/certs/ca-certificates.crt; fi; apk add --no-cache openssh python3 && adduser -D -s /bin/sh operator && addgroup operator docker && passwd -d operator && mkdir -p /home/operator/.ssh /run/sshd && ssh-keygen -A
COPY entrypoint.sh /test-entrypoint.sh
RUN chmod 755 /test-entrypoint.sh
EXPOSE 22
ENTRYPOINT ["/test-entrypoint.sh"]
