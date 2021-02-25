.PHONY: clean all

all: \
	recordings/TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA.yaml

clean:
	rm -f recordings/*.yaml

recordings/%.yaml:
	python test_ssl3_$*.py
