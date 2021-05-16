.PHONY: clean all init root root-rsa init-root-rsa root-ecdsa ca ca-rsa ca-ecdsa

OPENSSL ?= $(shell which openssl)
export TLSMATE_CA_PORT ?= 44400
TLSMATE_CA_RSA_OCSP_PORT ?= 44401
TLSMATE_CA_ECDSA_OCSP_PORT ?= 44402
export CA_NAME = root-rsa
export OCSP_PORT = ${TLSMATE_CA_RSA_OCSP_PORT}

all: root ca server client crl certs/ca-certificates.pem

clean:
	rm -rf crl certs chains private db tmp dsa_params.pem

root: root-rsa root-ecdsa
root-rsa: certs/root-rsa.crt
root-ecdsa: certs/root-ecdsa.crt
ca: ca-rsa ca-ecdsa
ca-rsa: certs/ca-rsa.crt
ca-ecdsa: certs/ca-ecdsa.crt
server: server-rsa server-ecdsa server-ed25519 server-ed448 server-dsa server-revoked-rsa
server-rsa: certs/server-rsa.crt
server-ecdsa: certs/server-ecdsa.crt
server-ed25519: certs/server-ed25519.crt
server-ed448: certs/server-ed448.crt
server-dsa: certs/server-dsa.crt
server-revoked-rsa: certs/server-revoked-rsa.crt
client: client-rsa client-ecdsa
client-rsa: certs/client-rsa.crt
client-ecdsa: certs/client-ecdsa.crt
crl: crl-ca-rsa crl-ca-ecdsa
crl-ca-rsa: crl/ca-rsa.crl
crl-ca-ecdsa: crl/ca-ecdsa.crl

db/%/db/index:
	mkdir -p crl certs/openssl chains private db tmp
	mkdir -p db/$*
	touch db/$*/index
	${OPENSSL} rand -hex 8 | awk '{print "0" $$0}' | sed 's/.$$//g' > db/$*/serial
	echo 01 > db/$*/crlnumber

certs/root-rsa.crt:
	make db/root-rsa/db/index
	${OPENSSL} req -config openssl.cnf -x509 -extensions root_ext -nodes \
	-subj "/C=DE/O=The TlsMate Company/CN=localhost Root CA RSA" \
	-keyout private/root-rsa.key -out certs/root-rsa.crt -newkey rsa:2048

certs/root-ecdsa.crt:
	make db/root-ecdsa/db/index
	${OPENSSL} req -config openssl.cnf -x509 -extensions root_ext -nodes \
	-subj "/C=DE/O=The TlsMate Company/CN=localhost Root CA ECDSA" \
	-keyout private/root-ecdsa.key -out certs/root-ecdsa.crt \
	-newkey ec -pkeyopt ec_paramgen_curve:secp384r1

certs/ca-rsa.crt: export CA_NAME=root-rsa
certs/ca-rsa.crt: certs/root-rsa.crt
	make db/ca-rsa/db/index
	${OPENSSL} req -config openssl.cnf -nodes \
	-subj "/C=DE/O=The TlsMate Company/CN=localhost Intermediate CA RSA" \
	-keyout private/ca-rsa.key -out tmp/req.pem -newkey rsa:2048
	export CA=root-rsa
	${OPENSSL} ca -batch -notext -config openssl.cnf \
	-extensions root_ext -in tmp/req.pem -out certs/ca-rsa.crt

certs/ca-ecdsa.crt: export CA_NAME=root-ecdsa
certs/ca-ecdsa.crt: certs/root-ecdsa.crt
	make db/ca-ecdsa/db/index
	${OPENSSL} req -config openssl.cnf -nodes \
	-subj "/C=DE/O=The TlsMate Company/CN=localhost Intermediate CA ECDSA" \
	-newkey ec -pkeyopt ec_paramgen_curve:secp384r1 \
	-keyout private/ca-ecdsa.key -out tmp/req.pem
	export CA=root-ecdsa
	${OPENSSL} ca -batch -notext -config openssl.cnf \
	-extensions root_ext -in tmp/req.pem -out certs/ca-ecdsa.crt

certs/server-rsa.crt: export OCSP_PORT=${TLSMATE_CA_RSA_OCSP_PORT}
certs/server-rsa.crt: export CA_NAME=ca-rsa
certs/server-rsa.crt: certs/ca-rsa.crt
	${OPENSSL} req -config openssl.cnf -nodes \
	-subj "/C=DE/O=The TlsMate Company (Server side) RSA/CN=localhost" \
	-newkey rsa:2048 -keyout private/server-rsa.key -out tmp/req.pem
	export CA=ca-rsa
	${OPENSSL} ca -batch -notext -config openssl.cnf \
	-extensions server_ext -in tmp/req.pem -out certs/server-rsa.crt
	ln -s ../certs/ca-rsa.crt chains/server-rsa.chn

certs/server-ecdsa.crt: export OCSP_PORT=${TLSMATE_CA_ECDSA_OCSP_PORT}
certs/server-ecdsa.crt: export CA_NAME=ca-ecdsa
certs/server-ecdsa.crt: certs/ca-ecdsa.crt
	${OPENSSL} req -config openssl.cnf -nodes \
	-subj "/C=DE/O=The TlsMate Company (Server side) ECDSA/CN=localhost" \
	-newkey ec -pkeyopt ec_paramgen_curve:secp384r1 \
	-keyout private/server-ecdsa.key -out tmp/req.pem
	${OPENSSL} ca -batch -notext -config openssl.cnf \
	-extensions server_ext -in tmp/req.pem -out certs/server-ecdsa.crt
	ln -s ../certs/ca-ecdsa.crt chains/server-ecdsa.chn

certs/server-ed25519.crt: export OCSP_PORT=${TLSMATE_CA_ECDSA_OCSP_PORT}
certs/server-ed25519.crt: export CA_NAME=ca-ecdsa
certs/server-ed25519.crt: certs/ca-ecdsa.crt
	${OPENSSL} genpkey -algorithm ED25519 -out private/server-ed25519.key
	${OPENSSL} req -new -batch -subj "/C=DE/O=The TlsMate Company (Server side) Ed25519/CN=localhost" \
	-key private/server-ed25519.key -out tmp/req.pem
	${OPENSSL} ca -batch -notext -config openssl.cnf \
	-extensions server_ext -in tmp/req.pem -out certs/server-ed25519.crt
	ln -s ../certs/ca-ecdsa.crt chains/server-ed25519.chn

certs/server-ed448.crt: export OCSP_PORT=${TLSMATE_CA_ECDSA_OCSP_PORT}
certs/server-ed448.crt: export CA_NAME=ca-ecdsa
certs/server-ed448.crt: certs/ca-ecdsa.crt
	${OPENSSL} genpkey -algorithm ED448 -out private/server-ed448.key
	${OPENSSL} req -new -batch -subj "/C=DE/O=The TlsMate Company (Server side) Ed448/CN=localhost" \
	-key private/server-ed448.key -out tmp/req.pem
	${OPENSSL} ca -batch -notext -config openssl.cnf \
	-extensions server_ext -in tmp/req.pem -out certs/server-ed448.crt
	ln -s ../certs/ca-ecdsa.crt chains/server-ed448.chn

certs/server-dsa.crt: export OCSP_PORT=${TLSMATE_CA_RSA_OCSP_PORT}
certs/server-dsa.crt: export CA_NAME=ca-rsa
certs/server-dsa.crt: certs/ca-ecdsa.crt
	${OPENSSL} dsaparam -out dsa_params.pem 3072
	${OPENSSL} gendsa -out private/server-dsa.key dsa_params.pem
	${OPENSSL} req -new -batch -subj "/C=DE/O=The TlsMate Company (Server side) DSA/CN=localhost" \
	-key private/server-dsa.key -out tmp/req.pem
	${OPENSSL} ca -batch -notext -config openssl.cnf \
	-extensions server_ext -in tmp/req.pem -out certs/server-dsa.crt
	ln -s ../certs/ca-rsa.crt chains/server-dsa.chn

certs/server-revoked-rsa.crt: export OCSP_PORT=${TLSMATE_CA_RSA_OCSP_PORT}
certs/server-revoked-rsa.crt: export CA_NAME=ca-rsa
certs/server-revoked-rsa.crt: certs/ca-rsa.crt
	${OPENSSL} req -config openssl.cnf -nodes \
	-subj "/C=DE/O=The TlsMate Company (Server side) RSA/CN=revoked.localhost" \
	-newkey rsa:2048 -keyout private/server-revoked-rsa.key -out tmp/req.pem
	export CA=ca-rsa
	${OPENSSL} ca -batch -notext -config openssl.cnf \
	-extensions server_ext -in tmp/req.pem -out certs/server-revoked-rsa.crt
	${OPENSSL} ca -revoke certs/server-revoked-rsa.crt -config openssl.cnf \
	-crl_reason superseded -keyfile private/ca-rsa.key -cert certs/ca-rsa.crt
	ln -s ../certs/ca-rsa.crt chains/server-revoked-rsa.chn

certs/client-rsa.crt: export CA_NAME=ca-rsa
certs/client-rsa.crt: certs/ca-rsa.crt
	${OPENSSL} req -config openssl.cnf -nodes \
	-subj "/C=DE/O=The TlsMate Company (Client side) RSA/CN=client@tlsmate.org" \
	-newkey rsa:2048 -keyout private/client-rsa.key -out tmp/req.pem
	export CA=ca-rsa
	${OPENSSL} ca -batch -notext -config openssl.cnf \
	-extensions client_ext -in tmp/req.pem -out certs/client-rsa.crt
	ln -s ../certs/ca-rsa.crt chains/client-rsa.chn

certs/client-ecdsa.crt: export CA_NAME=ca-ecdsa
certs/client-ecdsa.crt: certs/ca-ecdsa.crt
	${OPENSSL} req -config openssl.cnf -nodes \
	-subj "/C=DE/O=The TlsMate Company (Client side) ECDSA/CN=client@tlsmate.org" \
	-newkey ec -pkeyopt ec_paramgen_curve:secp384r1 \
	-keyout private/client-ecdsa.key -out tmp/req.pem
	export CA=ca-ecdsa
	${OPENSSL} ca -batch -notext -config openssl.cnf \
	-extensions client_ext -in tmp/req.pem -out certs/client-ecdsa.crt
	ln -s ../certs/ca-ecdsa.crt chains/client-ecdsa.chn

crl/ca-rsa.crl: export CA_NAME=ca-rsa
crl/ca-rsa.crl: certs/server-revoked-rsa.crt
	${OPENSSL} ca -config openssl.cnf -gencrl -keyfile private/ca-rsa.key -cert certs/ca-rsa.crt -out crl/ca-rsa.crl.pem
	${OPENSSL} crl -inform PEM -in crl/ca-rsa.crl.pem -outform DER -out crl/ca-rsa.crl

crl/ca-ecdsa.crl: export CA_NAME=ca-ecdsa
crl/ca-ecdsa.crl: certs/ca-ecdsa.crt
	${OPENSSL} ca -config openssl.cnf -gencrl -keyfile private/ca-ecdsa.key -cert certs/ca-ecdsa.crt -out crl/ca-ecdsa.crl.pem
	${OPENSSL} crl -inform PEM -in crl/ca-ecdsa.crl.pem -outform DER -out crl/ca-ecdsa.crl

certs/ca-certificates.pem: certs/root-rsa.crt certs/root-ecdsa.crt certs/ca-rsa.crt certs/ca-ecdsa.crt
	cat certs/root-rsa.crt certs/root-ecdsa.crt certs/ca-rsa.crt certs/ca-ecdsa.crt > certs/ca-certificates.pem 
