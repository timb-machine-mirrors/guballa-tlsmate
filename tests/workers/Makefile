.PHONY: clean all

all: \
	recordings/recorder_eval_cipher_suites_openssl1_0_2.yaml \
	recordings/recorder_supported_groups_openssl1_0_2.yaml \
	recordings/recorder_sig_algos_openssl1_0_2.yaml \
	recordings/recorder_eval_cipher_suites_openssl3_0_0.yaml \
	recordings/recorder_eval_cipher_suites_chacha20_pref_openssl3_0_0.yaml \
	recordings/recorder_supported_groups_openssl3_0_0.yaml \
	recordings/recorder_sig_algos_openssl3_0_0.yaml \
	recordings/recorder_eval_cipher_suites_server_prio_openssl1_0_2.yaml \
	recordings/recorder_eval_cipher_suites_ssl2.yaml \
	recordings/recorder_ccs_injection_nok_openssl1_0_1g.yaml \
	recordings/recorder_ccs_injection_ok_openssl1_0_2.yaml \
	recordings/recorder_dh_groups.yaml \
	recordings/recorder_compression.yaml \
	recordings/recorder_encrypt_then_mac.yaml \
	recordings/recorder_grease.yaml \
	recordings/recorder_heartbeat.yaml \
	recordings/recorder_heartbleed.yaml \
	recordings/recorder_master_secret.yaml \
	recordings/recorder_renegotiation.yaml \
	recordings/recorder_resumption.yaml \
	recordings/recorder_robot_ok.yaml \
	recordings/recorder_robot_weak_oracle.yaml \
	recordings/recorder_basic_profile_wolfssl3_12_0.yaml \
	recordings/recorder_scan_info.yaml \
	recordings/recorder_ephemeral_key_reuse.yaml \
	recordings/recorder_ephemeral_key_reuse_tls13.yaml \
	recordings/recorder_ocsp_multi_stapling_ok.yaml \
	recordings/recorder_ocsp_stapling_tls12_not_supported.yaml \
	recordings/recorder_ocsp_stapling_tls12_ok.yaml \
	recordings/recorder_ocsp_stapling_tls13_not_supported.yaml \
	recordings/recorder_ocsp_stapling_tls13_ok.yaml

recordings/recorder_supported_groups_openssl%.yaml: recordings/recorder_eval_cipher_suites_openssl$*.yaml

recordings/recorder_sig_algos_openssl%.yaml: recordings/recorder_supported_groups_openssl$*.yaml

recordings/recorder_ccs_injection%.yaml: recordings/recorder_sig_algos_openssl1_0_2.yaml

recordings/recorder_dh_groups.yaml: recordings/recorder_sig_algos_openssl1_0_2.yaml

recordings/recorder_compression.yaml: recordings/recorder_sig_algos_openssl1_0_2.yaml

recordings/recorder_encrypt_then_mac.yaml: recordings/recorder_sig_algos_openssl1_0_2.yaml

recordings/recorder_grease.yaml: recordings/recorder_resumption.yaml

recordings/recorder_heartbeat.yaml: recordings/recorder_sig_algos_openssl1_0_2.yaml

recordings/recorder_heartbleed.yaml: recordings/recorder_sig_algos_openssl1_0_2.yaml

recordings/recorder_master_secret.yaml: recordings/recorder_sig_algos_openssl1_0_2.yaml

recordings/recorder_renegotiation.yaml: recordings/recorder_sig_algos_openssl1_0_2.yaml

recordings/recorder_resumption.yaml: recordings/recorder_sig_algos_openssl3_0_0.yaml

recordings/recorder_robot_ok.yaml: recordings/recorder_sig_algos_openssl1_0_2.yaml

recordings/recorder_robot_weak_oracle.yaml: recordings/recorder_basic_profile_wolfssl3_12_0.yaml

recordings/recorder_scan_info.yaml: recordings/recorder_sig_algos_openssl3_0_0.yaml

recordings/recorder_ocsp_multi_stapling_ok.yaml: recordings/recorder_basic_profile_wolfssl3_12_0.yaml

recordings/recorder_ocsp_stapling_tls12_not_supported.yaml: recordings/recorder_sig_algos_openssl1_0_2.yaml

recordings/recorder_ocsp_stapling_tls12_ok.yaml: recordings/recorder_sig_algos_openssl1_0_2.yaml

recordings/recorder_ocsp_stapling_tls13_not_supported.yaml: recordings/recorder_sig_algos_openssl3_0_0.yaml

recordings/recorder_ocsp_stapling_tls13_ok.yaml: recordings/recorder_sig_algos_openssl3_0_0.yaml

clean:
	rm -f recordings/*.yaml

recordings/recorder_%.yaml:
	python test_$*.py
