.PHONY: clean all openssl1_0_1e openssl1_0_1g openssl1_0_2 openssl1_1_1 openssl3_0_0 wolfssl3_12_0

all: openssl1_0_1e \
	openssl1_0_1g \
	openssl1_0_2 \
	openssl1_1_1 \
	openssl3_0_0 \
	wolfssl3_12_0

clean:
	rm -rf openssl1_0_1e openssl1_0_1g openssl1_0_2 openssl1_1_1 openssl3_0_0 wolfssl3_12_0

%/config:
	rm -rf $*
	git clone --depth 1 --branch ${TAG} https://github.com/openssl/openssl.git $*

%/Makefile: %/config
	(cd $* && ./config no-shared ${CONFIG} && make depend)

%/apps/openssl: %/Makefile
	(cd $* && make)

openssl1_0_1e: export TAG = OpenSSL_1_0_1e
openssl1_0_1e: openssl1_0_1e/apps/openssl

openssl1_0_1g: export TAG = OpenSSL_1_0_1g
openssl1_0_1g: openssl1_0_1g/apps/openssl

openssl1_0_2: export TAG = OpenSSL_1_0_2u
openssl1_0_2: export CONFIG = enable-ssl2
openssl1_0_2: openssl1_0_2/apps/openssl

openssl1_1_1: export TAG = OpenSSL_1_1_1k
openssl1_1_1: openssl1_1_1/apps/openssl

openssl3_0_0: export TAG = openssl-3.0.0-alpha16
openssl3_0_0: openssl3_0_0/apps/openssl

# Weak ROBOT oracle
wolfssl3_12_0:
	git clone --depth 1 --branch v3.12.0-stable https://github.com/wolfSSL/wolfssl.git wolfssl3_12_0
	(cd wolfssl3_12_0 && ./autogen.sh && ./configure CFLAGS="-DWOLFSSL_STATIC_RSA")
	(cd wolfssl3_12_0 && sed -i 's/-Werror //g' Makefile && make)
