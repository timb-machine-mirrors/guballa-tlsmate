.PHONY: clean all

all: \
	recordings/ClientProfiles.yaml

clean:
	rm -f recordings/*.yaml

recordings/%.yaml:
	python test_features_$*.py
