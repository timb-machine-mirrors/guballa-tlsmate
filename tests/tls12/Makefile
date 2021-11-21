.PHONY: clean all

all: \
	recordings/ClientAuth_ECDSA_SHA256_posthandshake.yaml \
	recordings/ClientAuth_ECDSA_SHA256.yaml \
	recordings/ClientAuth_PSS_RSAE_SHA256_posthandshake.yaml \
	recordings/ClientAuth_PSS_RSAE_SHA256.yaml \
	recordings/ClientAuth_RSA_SHA256_posthandshake.yaml \
	recordings/ClientAuth_RSA_SHA256.yaml \
	recordings/EncryptThenMac.yaml \
	recordings/ExtendedMasterSecret.yaml \
	recordings/Heartbeat.yaml \
	recordings/Legacy_Renegotiation_Client.yaml \
	recordings/Legacy_Renegotiation_Server.yaml \
	recordings/ResumptionById.yaml \
	recordings/ResumptionByTicket.yaml \
	recordings/SecureRenegotiationSCSV.yaml \
	recordings/SecureRenegotiation.yaml \
	recordings/SupportedGroups_BRAINPOOLP256R1.yaml \
	recordings/SupportedGroups_BRAINPOOLP384R1.yaml \
	recordings/SupportedGroups_BRAINPOOLP512R1.yaml \
	recordings/SupportedGroups_SECP224R1.yaml \
	recordings/SupportedGroups_SECP256K1.yaml \
	recordings/SupportedGroups_SECP256R1.yaml \
	recordings/SupportedGroups_SECP384R1.yaml \
	recordings/SupportedGroups_SECP521R1.yaml \
	recordings/SupportedGroups_SECT163K1.yaml \
	recordings/SupportedGroups_SECT163R2.yaml \
	recordings/SupportedGroups_SECT233K1.yaml \
	recordings/SupportedGroups_SECT233R1.yaml \
	recordings/SupportedGroups_SECT283K1.yaml \
	recordings/SupportedGroups_SECT283R1.yaml \
	recordings/SupportedGroups_SECT409K1.yaml \
	recordings/SupportedGroups_SECT409R1.yaml \
	recordings/SupportedGroups_SECT571K1.yaml \
	recordings/SupportedGroups_SECT571R1.yaml \
	recordings/SupportedGroups_X25519.yaml \
	recordings/SupportedGroups_X448.yaml \
	recordings/TLS_DHE_RSA_WITH_AES_128_GCM_SHA256.yaml \
	recordings/TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256.yaml \
	recordings/TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8.yaml \
	recordings/TLS_ECDHE_ECDSA_WITH_AES_128_CCM.yaml \
	recordings/TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8.yaml \
	recordings/TLS_ECDHE_ECDSA_WITH_AES_256_CCM.yaml \
	recordings/TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256.yaml \
	recordings/TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA.yaml \
	recordings/TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256.yaml \
	recordings/TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA.yaml \
	recordings/TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384.yaml \
	recordings/TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256.yaml \
	recordings/TLS_RSA_WITH_AES_128_GCM_SHA256.yaml \
	recordings/TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256_ED25519.yaml \
	recordings/TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256_ED448.yaml \
	recordings/TLS_DHE_DSS_WITH_AES_128_CBC_SHA256.yaml

clean:
	rm -f recordings/*.yaml

recordings/%.yaml:
	python test_tls12_$*.py
