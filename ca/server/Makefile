all: rsa rsa-revoked ecdsa dsa ed25519 ed448

OPENSSLPATH ?= /usr/bin

clean:
	/bin/rm -rf certs private csr issuedcerts db chains dsa_params.pem

server-dirs:
	mkdir -p certs
	mkdir -p private
	mkdir -p chains

cert/server-rsa.crt: server-dirs
	${OPENSSLPATH}/openssl genrsa -out private/server-rsa.key 2048
	${OPENSSLPATH}/openssl req -new -batch -subj "/C=DE/O=The TlsMate Company (Server side) RSA/CN=localhost" -key private/server-rsa.key -out ../inter-ca-rsa/csr/server-rsa.csr
	(cd ../inter-ca-rsa && make server-rsa.csr)
	cp ../inter-ca-rsa/certs/server-rsa.crt certs
	cat ../inter-ca-rsa/certs/inter-ca-rsa.crt > chains/server-rsa.pem

cert/server-revoked-rsa.crt: server-dirs
	${OPENSSLPATH}/openssl genrsa -out private/server-revoked-rsa.key 2048
	${OPENSSLPATH}/openssl req -new -batch -subj "/C=DE/O=The TlsMate Company (Server side) RSA/CN=revoked.localhost" -key private/server-revoked-rsa.key -out ../inter-ca-rsa/csr/server-revoked-rsa.csr
	(cd ../inter-ca-rsa && make server-revoked-rsa.csr)
	cp ../inter-ca-rsa/certs/server-revoked-rsa.crt certs
	cat ../inter-ca-rsa/certs/inter-ca-rsa.crt > chains/server-revoked-rsa.pem

cert/server-ecdsa.crt: server-dirs
	${OPENSSLPATH}/openssl ecparam -name prime256v1 -genkey -out private/server-ecdsa.key
	${OPENSSLPATH}/openssl req -new -batch -subj "/C=DE/O=The TlsMate Company (Server side) ECDSA/CN=localhost" -key private/server-ecdsa.key -out ../inter-ca-ecdsa/csr/server-ecdsa.csr
	(cd ../inter-ca-ecdsa && make server-ecdsa.csr)
	cp ../inter-ca-ecdsa/certs/server-ecdsa.crt certs
	cat ../inter-ca-ecdsa/certs/inter-ca-ecdsa.crt > chains/server-ecdsa.pem

cert/server-dsa.crt: server-dirs
	${OPENSSLPATH}/openssl dsaparam -out dsa_params.pem 3072
	${OPENSSLPATH}/openssl gendsa -out private/server-dsa.key dsa_params.pem
	${OPENSSLPATH}/openssl req -new -batch -subj "/C=DE/O=The TlsMate Company (Server side) DSA/CN=localhost" -key private/server-dsa.key -out ../inter-ca-rsa/csr/server-dsa.csr
	(cd ../inter-ca-rsa && make server-dsa.csr)
	cp ../inter-ca-rsa/certs/server-dsa.crt certs
	cat ../inter-ca-rsa/certs/inter-ca-rsa.crt > chains/server-dsa.pem

cert/server-ed25519.crt: server-dirs
	${OPENSSLPATH}/openssl genpkey -algorithm ED25519 -out private/server-ed25519.key
	${OPENSSLPATH}/openssl req -new -batch -subj "/C=DE/O=The TlsMate Company (Server side) Ed25519/CN=localhost" -key private/server-ed25519.key -out ../inter-ca-ecdsa/csr/server-ed25519.csr
	(cd ../inter-ca-ecdsa && make server-ed25519.csr)
	cp ../inter-ca-ecdsa/certs/server-ed25519.crt certs
	cat ../inter-ca-ecdsa/certs/inter-ca-ecdsa.crt > chains/server-ed25519.pem

cert/server-ed448.crt: server-dirs
	${OPENSSLPATH}/openssl genpkey -algorithm ed448 -out private/server-ed448.key
	${OPENSSLPATH}/openssl req -new -batch -subj "/C=DE/O=The TlsMate Company (Server side) Ed448/CN=localhost" -key private/server-ed448.key -out ../inter-ca-ecdsa/csr/server-ed448.csr
	(cd ../inter-ca-ecdsa && make server-ed448.csr)
	cp ../inter-ca-ecdsa/certs/server-ed448.crt certs
	cat ../inter-ca-ecdsa/certs/inter-ca-ecdsa.crt > chains/server-ed448.pem

rsa: cert/server-rsa.crt

rsa-revoked: cert/server-revoked-rsa.crt
	(cd ../inter-ca-rsa && make revokation)

dsa: cert/server-dsa.crt

ecdsa: cert/server-ecdsa.crt

ed25519: cert/server-ed25519.crt

ed448: cert/server-ed448.crt
