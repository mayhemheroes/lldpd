FROM alpine:latest as builder
RUN apk add autoconf automake libtool \
	libevent-dev libxml2-dev jansson-dev \
        readline-dev libcap-dev bsd-compat-headers \
        alpine-sdk
WORKDIR /build
COPY . .
RUN ./autogen.sh
RUN ./configure \
		--prefix=/usr \
		--sysconfdir=/etc \
		--enable-pie \
		--enable-hardening \
		--without-embedded-libevent \
		--without-snmp \
                --with-xml \
		--with-privsep-user=_lldpd \
		--with-privsep-group=_lldpd \
		--with-privsep-chroot=/run/lldpd \
		--with-lldpd-ctl-socket=/run/lldpd.socket \
		--with-lldpd-pid-file=/run/lldpd.pid
RUN make
RUN make install DESTDIR=/lldpd
WORKDIR /build/tests
RUN make check
RUN mkdir -p /deps
RUN ldd /build/tests/decode | tr -s '[:blank:]' '\n' | grep '^/' | xargs -I % sh -c 'cp % /deps;'

FROM alpine:latest as package

COPY --from=builder /deps /deps
COPY --from=builder /build/tests/decode /build/tests/decode
ENV LD_LIBRARY_PATH=/deps
