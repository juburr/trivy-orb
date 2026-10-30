# For trivy-orb's misconfiguration tests: it runs as root (no USER) and
# fetches with ADD. Never built.
FROM alpine:3.20
ADD https://example.com/app.tar.gz /opt/app.tar.gz
CMD ["/bin/sh"]
