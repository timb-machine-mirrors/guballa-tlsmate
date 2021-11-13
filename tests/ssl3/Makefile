.HONY: clean all

all: \
	recordings/TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA.yaml \
	recordings/TLS_RSA_WITH_AES_128_CBC_SHA.yaml \
	recordings/TLS_RSA_WITH_RC4_128_MD5.yaml

clean:
	rm -f recordings/*.yaml

recordings/%.yaml:
	python test_ssl3_$*.py
