.PHONY: clean all

all: \
	recordings/ServerHello.yaml

clean:
	rm -f recordings/*.yaml

recordings/%.yaml:
	python test_ssl2_$*.py
