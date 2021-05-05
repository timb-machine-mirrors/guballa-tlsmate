.PHONY: clean all

all: \
	recordings/TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA.yaml \
	recordings/TLS_DH_ANON_WITH_AES_128_CBC_SHA.yaml

clean:
	rm -f recordings/*.yaml

recordings/%.yaml:
	python test_tls10_$*.py
