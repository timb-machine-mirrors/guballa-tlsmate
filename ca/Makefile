.PHONY: clean all init root root-rsa init-root-rsa root-ecdsa ca ca-rsa ca-ecdsa

OPENSSL ?= $(shell which openssl)
export TLSMATE_CA_PORT ?= 44400
TLSMATE_CA_RSA_OCSP_PORT ?= 44401
TLSMATE_CA_ECDSA_OCSP_PORT ?= 44402
TLSMATE_ROOT_RSA_OCSP_PORT ?= 44403
TLSMATE_ROOT_ECDSA_OCSP_PORT ?= 44404
export CA_NAME = root-rsa
export OCSP_PORT = ${TLSMATE_CA_RSA_OCSP_PORT}

all: root ca server client crl certs/ca-certificates.pem certs/root-certificates.pem invalid-chain

clean:
	rm -rf crl certs chains private db tmp dsa_params.pem

root: root-rsa root-ecdsa
root-rsa: certs/root-rsa.crt
root-ecdsa: certs/root-ecdsa.crt
ca: ca-rsa ca-2nd-rsa ca-ecdsa
ca-rsa: certs/ca-rsa.crt
ca-2nd-rsa: certs/ca-2nd-rsa.crt
ca-ecdsa: certs/ca-ecdsa.crt
server: server-rsa server-ecdsa server-ed25519 server-ed448 server-dsa server-ecdsa-rsa server-revoked-rsa server-expired-rsa server-no-ids-rsa
server-rsa: certs/server-rsa.crt
server-ecdsa: certs/server-ecdsa.crt
server-ed25519: certs/server-ed25519.crt
server-ed448: certs/server-ed448.crt
server-ecdsa-rsa: certs/server-ecdsa-rsa.crt
server-dsa: certs/server-dsa.crt
server-revoked-rsa: certs/server-revoked-rsa.crt
server-expired-rsa: certs/server-expired-rsa.crt
server-no-ids-rsa: certs/server-no-ids-rsa.crt
client: client-rsa client-ecdsa
client-rsa: certs/client-rsa.crt
client-ecdsa: certs/client-ecdsa.crt
crl: crl-ca-rsa crl-ca-ecdsa crl-root-rsa crl-root-ecdsa
crl-ca-rsa: crl/ca-rsa.crl
crl-ca-ecdsa: crl/ca-ecdsa.crl
crl-root-rsa: crl/root-rsa.crl
crl-root-ecdsa: crl/root-ecdsa.crl
invalid-chain: chains/server-invalid-sequence-rsa.chn

certs/%.crt: certs/%.pem
	${OPENSSL} x509 -inform pem -in $< -outform der -out $@


db/%/db/index:
	mkdir -p crl certs/openssl chains private db tmp
	mkdir -p db/$*
	touch db/$*/index
	${OPENSSL} rand -hex 8 | awk '{print "0" $$0}' | sed 's/.$$//g' > db/$*/serial
	echo 01 > db/$*/crlnumber

certs/root-rsa.pem:
	make db/root-rsa/db/index
	${OPENSSL} req -config openssl.cnf -x509 -extensions root_ext -nodes \
	-subj "/C=DE/O=The TlsMate Company/CN=localhost Root CA RSA" -days 3650 \
	-keyout private/root-rsa.key -out certs/root-rsa.pem -newkey rsa:2048

certs/root-ecdsa.pem:
	make db/root-ecdsa/db/index
	${OPENSSL} req -config openssl.cnf -x509 -extensions root_ext -nodes \
	-subj "/C=DE/O=The TlsMate Company/CN=localhost Root CA ECDSA" -days 3650 \
	-keyout private/root-ecdsa.key -out certs/root-ecdsa.pem \
	-newkey ec -pkeyopt ec_paramgen_curve:secp384r1

certs/ca-rsa.pem: export OCSP_PORT=${TLSMATE_ROOT_RSA_OCSP_PORT}
certs/ca-rsa.pem: export CA_NAME=root-rsa
certs/ca-rsa.pem: certs/root-rsa.pem
	make db/ca-rsa/db/index
	${OPENSSL} req -config openssl.cnf -nodes \
	-subj "/C=DE/O=The TlsMate Company/CN=localhost Intermediate CA RSA" \
	-keyout private/ca-rsa.key -out tmp/req.pem -newkey rsa:2048
	${OPENSSL} ca -batch -notext -config openssl.cnf \
	-extensions ca_ext -in tmp/req.pem -out certs/ca-rsa.pem

certs/ca-ecdsa.pem: export OCSP_PORT=${TLSMATE_ROOT_ECDSA_OCSP_PORT}
certs/ca-ecdsa.pem: export CA_NAME=root-ecdsa
certs/ca-ecdsa.pem: certs/root-ecdsa.crt
	make db/ca-ecdsa/db/index
	${OPENSSL} req -config openssl.cnf -nodes \
	-subj "/C=DE/O=The TlsMate Company/CN=localhost Intermediate CA ECDSA" \
	-newkey ec -pkeyopt ec_paramgen_curve:secp384r1 \
	-keyout private/ca-ecdsa.key -out tmp/req.pem
	${OPENSSL} ca -batch -notext -config openssl.cnf \
	-extensions ca_ext -in tmp/req.pem -out certs/ca-ecdsa.pem

certs/ca-2nd-rsa.pem: export CA_NAME=root-ecdsa
certs/ca-2nd-rsa.pem: certs/ca-ecdsa.crt
	${OPENSSL} req -config openssl.cnf -nodes \
	-subj "/C=DE/O=The TlsMate Company/CN=localhost Intermediate CA RSA" \
	-keyout private/ca-2nd-rsa.key -out tmp/req.pem -newkey rsa:2048
	${OPENSSL} ca -batch -notext -config openssl.cnf \
	-extensions ca_ext -in tmp/req.pem -out certs/ca-2nd-rsa.pem

certs/server-rsa.pem: export OCSP_PORT=${TLSMATE_CA_RSA_OCSP_PORT}
certs/server-rsa.pem: export CA_NAME=ca-rsa
certs/server-rsa.pem: certs/ca-rsa.crt
	${OPENSSL} req -config openssl.cnf -nodes \
	-subj "/C=DE/O=The TlsMate Company (Server side) RSA/CN=localhost" \
	-newkey rsa:2048 -keyout private/server-rsa.key -out tmp/req.pem
	${OPENSSL} ca -batch -notext -config openssl.cnf \
	-extensions server_ext -in tmp/req.pem -out certs/server-rsa.pem
	ln -s ../certs/ca-rsa.pem chains/server-rsa.chn
	cat certs/server-rsa.pem certs/ca-rsa.pem certs/root-rsa.pem > chains/server-rsa-full.chn

certs/server-no-ids-rsa.pem: export OCSP_PORT=${TLSMATE_CA_RSA_OCSP_PORT}
certs/server-no-ids-rsa.pem: export CA_NAME=ca-rsa
certs/server-no-ids-rsa.pem: certs/ca-rsa.crt
	${OPENSSL} req -config openssl.cnf -nodes \
	-subj "/C=DE/O=The TlsMate Company (Server side, no ids) RSA/CN=localhost" \
	-newkey rsa:2048 -keyout private/server-no-ids-rsa.key -out tmp/req.pem
	${OPENSSL} ca -batch -notext -config openssl.cnf \
	-extensions server_ext_no_ids -in tmp/req.pem -out certs/server-no-ids-rsa.pem
	ln -s ../certs/ca-rsa.pem chains/server-no-ids-rsa.chn
	cat certs/server-no-ids-rsa.pem certs/ca-rsa.pem certs/root-rsa.pem > chains/server-no-ids-rsa-full.chn

# server certificate signature: ECDSA, issuing ca signature: RSA
certs/server-ecdsa-rsa.pem: export OCSP_PORT=${TLSMATE_CA_RSA_OCSP_PORT}
certs/server-ecdsa-rsa.pem: export CA_NAME=ca-rsa
certs/server-ecdsa-rsa.pem: certs/ca-rsa.crt
	${OPENSSL} req -config openssl.cnf -nodes \
	-subj "/C=DE/O=The TlsMate Company (Server side) ECDSA+RSA/CN=localhost" \
	-newkey ec -pkeyopt ec_paramgen_curve:secp384r1 \
	-keyout private/server-ecdsa-rsa.key -out tmp/req.pem
	${OPENSSL} ca -batch -notext -config openssl.cnf \
	-extensions server_ext -in tmp/req.pem -out certs/server-ecdsa-rsa.pem
	ln -s ../certs/ca-rsa.pem chains/server-ecdsa-rsa.chn

certs/server-ecdsa.pem: export OCSP_PORT=${TLSMATE_CA_ECDSA_OCSP_PORT}
certs/server-ecdsa.pem: export CA_NAME=ca-ecdsa
certs/server-ecdsa.pem: certs/ca-ecdsa.crt
	${OPENSSL} req -config openssl.cnf -nodes \
	-subj "/C=DE/O=The TlsMate Company (Server side) ECDSA/CN=localhost" \
	-newkey ec -pkeyopt ec_paramgen_curve:secp384r1 \
	-keyout private/server-ecdsa.key -out tmp/req.pem
	${OPENSSL} ca -batch -notext -config openssl.cnf \
	-extensions server_ext -in tmp/req.pem -out certs/server-ecdsa.pem
	ln -s ../certs/ca-ecdsa.pem chains/server-ecdsa.chn

certs/server-ed25519.pem: export OCSP_PORT=${TLSMATE_CA_ECDSA_OCSP_PORT}
certs/server-ed25519.pem: export CA_NAME=ca-ecdsa
certs/server-ed25519.pem: certs/ca-ecdsa.crt
	${OPENSSL} genpkey -algorithm ED25519 -out private/server-ed25519.key
	${OPENSSL} req -new -batch -subj "/C=DE/O=The TlsMate Company (Server side) Ed25519/CN=localhost" \
	-key private/server-ed25519.key -out tmp/req.pem
	${OPENSSL} ca -batch -notext -config openssl.cnf \
	-extensions server_ext -in tmp/req.pem -out certs/server-ed25519.pem
	ln -s ../certs/ca-ecdsa.pem chains/server-ed25519.chn

certs/server-ed448.pem: export OCSP_PORT=${TLSMATE_CA_ECDSA_OCSP_PORT}
certs/server-ed448.pem: export CA_NAME=ca-ecdsa
certs/server-ed448.pem: certs/ca-ecdsa.crt
	${OPENSSL} genpkey -algorithm ED448 -out private/server-ed448.key
	${OPENSSL} req -new -batch -subj "/C=DE/O=The TlsMate Company (Server side) Ed448/CN=localhost" \
	-key private/server-ed448.key -out tmp/req.pem
	${OPENSSL} ca -batch -notext -config openssl.cnf \
	-extensions server_ext -in tmp/req.pem -out certs/server-ed448.pem
	ln -s ../certs/ca-ecdsa.pem chains/server-ed448.chn

certs/server-dsa.pem: export OCSP_PORT=${TLSMATE_CA_RSA_OCSP_PORT}
certs/server-dsa.pem: export CA_NAME=ca-rsa
certs/server-dsa.pem: certs/ca-ecdsa.crt
	${OPENSSL} dsaparam -out dsa_params.pem 3072
	${OPENSSL} gendsa -out private/server-dsa.key dsa_params.pem
	${OPENSSL} req -new -batch -subj "/C=DE/O=The TlsMate Company (Server side) DSA/CN=localhost" \
	-key private/server-dsa.key -out tmp/req.pem
	${OPENSSL} ca -batch -notext -config openssl.cnf \
	-extensions server_ext -in tmp/req.pem -out certs/server-dsa.pem
	ln -s ../certs/ca-rsa.pem chains/server-dsa.chn

certs/server-revoked-rsa.pem: export OCSP_PORT=${TLSMATE_CA_RSA_OCSP_PORT}
certs/server-revoked-rsa.pem: export CA_NAME=ca-rsa
certs/server-revoked-rsa.pem: certs/ca-rsa.crt
	${OPENSSL} req -config openssl.cnf -nodes \
	-subj "/C=DE/O=The TlsMate Company (Server side) RSA/CN=revoked.localhost" \
	-newkey rsa:2048 -keyout private/server-revoked-rsa.key -out tmp/req.pem
	${OPENSSL} ca -batch -notext -config openssl.cnf \
	-extensions server_ext -in tmp/req.pem -out certs/server-revoked-rsa.pem
	${OPENSSL} ca -revoke certs/server-revoked-rsa.pem -config openssl.cnf \
	-crl_reason superseded -keyfile private/ca-rsa.key -cert certs/ca-rsa.pem
	ln -s ../certs/ca-rsa.pem chains/server-revoked-rsa.chn

certs/server-expired-rsa.pem: export OCSP_PORT=${TLSMATE_CA_RSA_OCSP_PORT}
certs/server-expired-rsa.pem: export CA_NAME=ca-rsa
certs/server-expired-rsa.pem: certs/ca-rsa.crt
	${OPENSSL} req -config openssl.cnf -nodes \
	-subj "/C=DE/O=The TlsMate Company (Server side) RSA/CN=expired.localhost" \
	-newkey rsa:2048 -keyout private/server-expired-rsa.key -out tmp/req.pem
	${OPENSSL} ca -batch -notext -config openssl.cnf \
	-extensions server_ext -in tmp/req.pem -out certs/server-expired-rsa.pem -startdate 200801010000Z -enddate 201001010000Z
	ln -s ../certs/ca-rsa.pem chains/server-expired-rsa.chn

certs/client-rsa.pem: export CA_NAME=ca-rsa
certs/client-rsa.pem: certs/ca-rsa.crt
	${OPENSSL} req -config openssl.cnf -nodes \
	-subj "/C=DE/O=The TlsMate Company (Client side) RSA/CN=client@tlsmate.org" \
	-newkey rsa:2048 -keyout private/client-rsa.key -out tmp/req.pem
	${OPENSSL} ca -batch -notext -config openssl.cnf \
	-extensions client_ext -in tmp/req.pem -out certs/client-rsa.pem
	cat certs/client-rsa.pem certs/ca-rsa.pem > chains/client-rsa.chn

certs/client-ecdsa.pem: export CA_NAME=ca-ecdsa
certs/client-ecdsa.pem: certs/ca-ecdsa.crt
	${OPENSSL} req -config openssl.cnf -nodes \
	-subj "/C=DE/O=The TlsMate Company (Client side) ECDSA/CN=client@tlsmate.org" \
	-newkey ec -pkeyopt ec_paramgen_curve:secp384r1 \
	-keyout private/client-ecdsa.key -out tmp/req.pem
	${OPENSSL} ca -batch -notext -config openssl.cnf \
	-extensions client_ext -in tmp/req.pem -out certs/client-ecdsa.pem
	cat certs/client-ecdsa.pem certs/ca-ecdsa.pem > chains/client-ecdsa.chn

crl/root-rsa.crl: certs/root-rsa.pem
	${OPENSSL} ca -config openssl.cnf -gencrl -keyfile private/root-rsa.key -cert certs/root-rsa.pem -out crl/root-rsa.crl.pem
	${OPENSSL} crl -inform PEM -in crl/root-rsa.crl.pem -outform DER -out crl/root-rsa.crl

crl/root-ecdsa.crl: certs/root-ecdsa.pem
	${OPENSSL} ca -config openssl.cnf -gencrl -keyfile private/root-ecdsa.key -cert certs/root-ecdsa.pem -out crl/root-ecdsa.crl.pem
	${OPENSSL} crl -inform PEM -in crl/root-ecdsa.crl.pem -outform DER -out crl/root-ecdsa.crl

crl/ca-rsa.crl: export CA_NAME=ca-rsa
crl/ca-rsa.crl: certs/server-revoked-rsa.crt
	${OPENSSL} ca -config openssl.cnf -gencrl -keyfile private/ca-rsa.key -cert certs/ca-rsa.pem -out crl/ca-rsa.crl.pem
	${OPENSSL} crl -inform PEM -in crl/ca-rsa.crl.pem -outform DER -out crl/ca-rsa.crl

crl/ca-ecdsa.crl: export CA_NAME=ca-ecdsa
crl/ca-ecdsa.crl: certs/ca-ecdsa.crt
	${OPENSSL} ca -config openssl.cnf -gencrl -keyfile private/ca-ecdsa.key -cert certs/ca-ecdsa.pem -out crl/ca-ecdsa.crl.pem
	${OPENSSL} crl -inform PEM -in crl/ca-ecdsa.crl.pem -outform DER -out crl/ca-ecdsa.crl

certs/ca-certificates.pem: certs/root-rsa.crt certs/root-ecdsa.crt certs/ca-rsa.crt certs/ca-ecdsa.crt
	cat certs/root-rsa.pem certs/root-ecdsa.pem certs/ca-rsa.pem certs/ca-ecdsa.pem > certs/ca-certificates.pem

certs/root-certificates.pem: certs/root-rsa.crt certs/root-ecdsa.crt
	cat certs/root-rsa.pem certs/root-ecdsa.pem > certs/root-certificates.pem

chains/server-invalid-sequence-rsa.chn:
	cat certs/root-rsa.pem certs/ca-rsa.pem > chains/server-invalid-sequence-rsa.chn

install:
	mkdir -p ../tests/ca/certs
	mkdir -p ../tests/ca/crl
	mkdir -p ../tests/ca/private
	mkdir -p ../tests/ca/chains
	cp certs/*.crt certs/*.pem ../tests/ca/certs
	cp crl/*.pem ../tests/ca/crl
	cp private/*.key ../tests/ca/private
	cp chains/*.chn ../tests/ca/chains
