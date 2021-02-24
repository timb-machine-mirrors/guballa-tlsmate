all: cert/root-ca-ecdsa.crt

OPENSSLPATH ?= /usr/bin

clean:
	/bin/rm -rf certs private csr issuedcerts db

root-ca-dirs:
	mkdir -p certs
	mkdir -p private
	mkdir -p csr
	mkdir -p issuedcerts
	mkdir -p db
	touch db/index
	${OPENSSLPATH}/openssl rand -hex 8 | awk '{print "0" $$0}' | sed 's/.$$//g' > db/serial
	echo 01 > db/crlnumber


cert/root-ca-ecdsa.crt: root-ca-dirs
	${OPENSSLPATH}/openssl ecparam -name prime256v1 -genkey -out private/root-ca-ecdsa.key
	${OPENSSLPATH}/openssl req -new -batch -subj "/C=DE/O=The TlsMate Company/CN=localhost Root CA ECDSA" -key private/root-ca-ecdsa.key -out csr/root-ca-ecdsa.csr
	${OPENSSLPATH}/openssl ca -batch -notext -selfsign -config root-ca.cnf -extensions root_ca_ext -days 3000 -in csr/root-ca-ecdsa.csr -out certs/root-ca-ecdsa.crt -keyfile private/root-ca-ecdsa.key

%-ecdsa.csr:
	${OPENSSLPATH}/openssl ca -batch -notext -config root-ca.cnf -extensions root_ca_ext -days 3000 -in csr/$*-ecdsa.csr -out certs/$*-ecdsa.crt -keyfile private/root-ca-ecdsa.key -cert certs/root-ca-ecdsa.crt
	cat certs/*.crt > certs/all-certs.pem
