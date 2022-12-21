FROM ubuntu:22.04  as builder
RUN apt-get update
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y autoconf automake libtool git pkg-config clang\
	libevent-dev libxml2-dev libjansson-dev \
        libreadline-dev libcap-dev libbsd-dev build-essential
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
RUN clang++ /build/mayhem/fuzz_pattern_match.cpp -fsanitize=fuzzer,address /build/src/daemon/.libs/liblldpd.a -o /fuzz

FROM ubuntu:22.04  as package
RUN apt-get update
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y libbsd-dev libevent-dev

COPY --from=builder /build/tests/decode /build/tests/decode
COPY --from=builder /fuzz /fuzz_pattern_match
