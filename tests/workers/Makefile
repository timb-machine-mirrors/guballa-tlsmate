.PHONY: clean all

all: \
	recordings/recorder_eval_cipher_suites_openssl1_0_2.yaml \
	recordings/recorder_supported_groups_openssl1_0_2.yaml \
	recordings/recorder_sig_algos_openssl1_0_2.yaml \
	recordings/recorder_eval_cipher_suites_openssl3_0_0.yaml \
	recordings/recorder_supported_groups_openssl3_0_0.yaml \
	recordings/recorder_sig_algos_openssl3_0_0.yaml

recordings/recorder_supported_groups_openssl%.yaml: recordings/recorder_eval_cipher_suites_openssl$*.yaml

recordings/recorder_sig_algos_openssl%.yaml: recordings/recorder_supported_groups_openssl$*.yaml

clean:
	rm -f recordings/*.yaml

recordings/recorder_%.yaml:
	python test_$*.py
