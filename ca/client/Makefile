all: rsa ecdsa

OPENSSLPATH ?= /usr/bin

clean:
	/bin/rm -rf certs private csr issuedcerts db chains

client-dirs:
	mkdir -p certs
	mkdir -p private
	mkdir -p chains

cert/client-rsa.crt: client-dirs
	${OPENSSLPATH}/openssl genrsa -out private/client-rsa.key 2048
	${OPENSSLPATH}/openssl req -new -batch -subj "/C=DE/O=The TlsMate Company (Client side) RSA/CN=client@tlsmate.org" -key private/client-rsa.key -out ../inter-ca-rsa/csr/client-rsa.csr
	(cd ../inter-ca-rsa && make client-rsa.csr)
	cp ../inter-ca-rsa/certs/client-rsa.crt certs
	cat certs/client-rsa.crt ../inter-ca-rsa/certs/inter-ca-rsa.crt > chains/client-chain-rsa.pem

cert/client-ecdsa.crt: client-dirs
	${OPENSSLPATH}/openssl ecparam -name prime256v1 -genkey -out private/client-ecdsa.key
	${OPENSSLPATH}/openssl req -new -batch -subj "/C=DE/O=The TlsMate Company (Client side) ECDSA/CN=client@tlsmate.org" -key private/client-ecdsa.key -out ../inter-ca-ecdsa/csr/client-ecdsa.csr
	(cd ../inter-ca-ecdsa && make client-ecdsa.csr)
	cp ../inter-ca-ecdsa/certs/client-ecdsa.crt certs
	cat certs/client-ecdsa.crt ../inter-ca-ecdsa/certs/inter-ca-ecdsa.crt > chains/client-chain-ecdsa.pem

rsa: cert/client-rsa.crt

ecdsa: cert/client-ecdsa.crt
