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
	recordings/recorder_ocsp_stapling_tls13_ok.yaml \
	recordings/recorder_downgrade_na.yaml \
	recordings/recorder_downgrade_ok.yaml \
	recordings/recorder_cbc_padding_oracle_high.yaml \
	recordings/recorder_cbc_padding_oracle_medium.yaml \
	recordings/recorder_cbc_padding_oracle_low.yaml \
	recordings/recorder_cbc_padding_oracle_ok.yaml \
	recordings/profile_text_ssl2.yaml \
	recordings/profile_text_openssl1_0_1e.yaml \
	recordings/profile_text_openssl3_0_0.yaml \
	recordings/recorder_eval_cipher_suites_openssl3_0_0_ed25519_ed448.yaml \
	recordings/recorder_eval_cipher_suites_openssl1_0_2_DSA.yaml \
	recordings/recorder_supported_groups_openssl3_0_0_ed25519_ed448.yaml \
	recordings/recorder_supported_groups_openssl1_0_2_DSA.yaml \
	recordings/recorder_sig_algos_openssl3_0_0_ed25519_ed448.yaml \
	recordings/recorder_sig_algos_openssl1_0_2_DSA.yaml \
	recordings/recorder_heartbleed_no_features.yaml

recordings/recorder_supported_groups_openssl%.yaml: recordings/recorder_eval_cipher_suites_openssl$*.yaml

recordings/recorder_sig_algos_openssl%.yaml: recordings/recorder_supported_groups_openssl$*.yaml

recordings/recorder_ccs_injection%.yaml: recordings/recorder_sig_algos_openssl1_0_2.yaml

recordings/recorder_dh_groups.yaml: recordings/recorder_sig_algos_openssl1_0_2.yaml

recordings/recorder_compression.yaml: recordings/recorder_sig_algos_openssl1_0_2.yaml

recordings/recorder_encrypt_then_mac.yaml: recordings/recorder_sig_algos_openssl1_0_2.yaml

recordings/recorder_grease.yaml: recordings/recorder_resumption.yaml

recordings/recorder_heartbeat.yaml: recordings/recorder_sig_algos_openssl1_0_2.yaml

recordings/recorder_heartbleed.yaml: recordings/recorder_sig_algos_openssl1_0_2.yaml

recordings/recorder_heartbleed_no_features.yaml: recordings/recorder_sig_algos_openssl1_0_2.yaml

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

recordings/recorder_downgrade_na.yaml: recordings/recorder_basic_profile_wolfssl3_12_0.yaml

recordings/recorder_downgrade_ok.yaml: recordings/recorder_sig_algos_openssl3_0_0.yaml

recordings/recorder_cbc_padding_oracle_%.yaml: recordings/recorder_sig_algos_openssl1_0_2.yaml

clean:
	rm -f recordings/*.yaml

recordings/recorder_%.yaml:
	python test_$*.py

recordings/profile_text_%.yaml:
	python test_text_server_profile_$*.py
