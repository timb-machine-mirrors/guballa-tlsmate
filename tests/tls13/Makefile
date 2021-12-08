.PHONY: clean all

all: \
	recordings/ClientAuth_ECDSA_SHA256_posthandshake.yaml \
	recordings/ClientAuth_ECDSA_SHA256.yaml \
	recordings/ClientAuth_PSS_RSAE_SHA256_posthandshake.yaml \
	recordings/ClientAuth_PSS_RSAE_SHA256.yaml \
	recordings/EarlyData.yaml \
	recordings/HelloRetryRequest.yaml \
	recordings/HelloRetryRequest_handshake.yaml \
	recordings/TLS_AES_128_CCM_8_SHA256.yaml \
	recordings/TLS_AES_128_CCM_SHA256.yaml \
	recordings/TLS_AES_128_GCM_SHA256.yaml \
	recordings/TLS_AES_256_GCM_SHA384.yaml \
	recordings/TLS_CHACHA20_POLY1305_SHA256.yaml

clean:
	rm -f recordings/*.yaml

recordings/%.yaml:
	python test_tls13_$*.py
