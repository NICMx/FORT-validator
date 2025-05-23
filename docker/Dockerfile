#--- Alpine build container ---
FROM alpine:latest AS builder
ARG FORT_VERSION=1.6.6

# Install compiler and dependencies
RUN apk --update --no-cache add build-base autoconf automake pkgconfig jansson-dev check-dev \
    openssl-dev openssl bsd-compat-headers rsync wget curl-dev libxml2 libxml2-dev

# Download FORT source code
WORKDIR /root
RUN wget https://github.com/NICMx/FORT-validator/releases/download/${FORT_VERSION}/fort-${FORT_VERSION}.tar.gz
RUN tar -xf fort-${FORT_VERSION}.tar.gz

# Compile and install FORT
WORKDIR /root/fort-${FORT_VERSION}
RUN ./configure && make && make install


#--- FORT image ---
FROM alpine:latest

# Install dependencies
RUN apk --update --no-cache add openssl jansson rsync tini libxml2 libcurl rtrlib

# Install FORT
COPY --from=builder /usr/local/bin/fort /usr/local/bin/fort
COPY --from=builder /usr/local/share/man/man8/fort.8 /usr/local/share/man/man8/fort.8

# Create required directories
RUN mkdir -p /var/local/fort && mkdir -p /etc/fort/tal

# Create default configuration
RUN yes yes | fort --init-tals --tal /etc/fort/tal
RUN echo '{ "tal":"/etc/fort/tal", "local-repository":"/var/local/fort" }' > /etc/fort/fort.conf


# Run FORT via TINI
EXPOSE 323
ENTRYPOINT ["tini", "-g", "--", "fort"]
CMD ["--configuration-file", "/etc/fort/fort.conf"]
