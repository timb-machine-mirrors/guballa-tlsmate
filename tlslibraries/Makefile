.PHONY: clean all openssl1_0_1e openssl1_0_1g openssl1_0_2 openssl1_1_1 openssl3_0_0 wolfssl3_12_0 wolfssl4_8_0

all: openssl1_0_1e \
	openssl1_0_1g \
	openssl1_0_2 \
	openssl1_1_1 \
	openssl3_0_0 \
	wolfssl3_12_0 \
	wolfssl4_8_0

clean:
	rm -rf openssl1_0_1e openssl1_0_1g openssl1_0_2 openssl1_1_1 openssl3_0_0 wolfssl3_12_0 wolfssl4_8_0

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


wolfssl4_8_0_certs:
	cat ../ca/certs/ca-rsa.pem ../ca/certs/root-rsa.pem > wolfssl4_8_0/certs/ocsp/intermediate1-ca-cert.pem
	cat ../ca/certs/root-rsa.pem > wolfssl4_8_0/certs/ocsp/intermediate2-ca-cert.pem

# OCSP multi stapling
wolfssl4_8_0:
	git clone --depth 1 --branch v4.8.0-stable https://github.com/wolfSSL/wolfssl.git wolfssl4_8_0
	(cd wolfssl4_8_0 && ./autogen.sh && ./configure --enable-ocspstapling --enable-ocspstapling2)
	(cd wolfssl4_8_0 && make)
	make wolfssl4_8_0_certs
