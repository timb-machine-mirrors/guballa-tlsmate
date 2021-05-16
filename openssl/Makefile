.PHONY: clean all openssl_1_0_1e openssl_1_0_1g openssl_1_0_2 openssl_1_1_1 openssl_3_0_0

all: openssl_1_0_1e \
	openssl_1_0_1g \
	openssl_1_0_2 \
	openssl_1_1_1 \
	openssl_3_0_0 \

clean:
	rm -rf openssl_1_0_1e openssl_1_0_1g openssl_1_0_2 openssl_1_1_1 openssl_3_0_0

%/config:
	rm -rf $*
	git clone --depth 1 --branch ${TAG} https://github.com/openssl/openssl.git $*

%/Makefile: %/config
	(cd $* && ./config ${CONFIG} && make depend)

%/apps/openssl: %/Makefile
	(cd $* && make)

openssl_1_0_1e: export TAG = OpenSSL_1_0_1e
openssl_1_0_1e: openssl1_0_1e/apps/openssl

openssl_1_0_1g: export TAG = OpenSSL_1_0_1g
openssl_1_0_1g: openssl1_0_1g/apps/openssl

openssl_1_0_2: export TAG = OpenSSL_1_0_2u
openssl_1_0_2: export CONFIG = enable-ssl2
openssl_1_0_2: openssl1_0_2/apps/openssl

openssl_1_1_1: export TAG = OpenSSL_1_1_1k
openssl_1_1_1: openssl1_1_1/apps/openssl

openssl_3_0_0: export TAG = openssl-3.0.0-alpha16
openssl_3_0_0: openssl3_0_0/apps/openssl
