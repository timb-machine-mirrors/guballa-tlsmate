.PHONY: clean all

all: \
	recordings/TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA.yaml \
	recordings/TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA.yaml \
	recordings/TLS_RSA_WITH_CAMELLIA_128_CBC_SHA.yaml \
	recordings/TLS_RSA_WITH_CAMELLIA_256_CBC_SHA.yaml \
	recordings/TLS_RSA_WITH_IDEA_CBC_SHA.yaml \
	recordings/TLS_RSA_WITH_RC4_128_SHA.yaml

clean:
	rm -f recordings/*.yaml

recordings/%.yaml:
	python test_tls11_$*.py
