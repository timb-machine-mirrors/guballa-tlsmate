all: cert/root-ca-rsa.crt

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


cert/root-ca-rsa.crt: root-ca-dirs
	${OPENSSLPATH}/openssl genrsa -out private/root-ca-rsa.key 2048
	${OPENSSLPATH}/openssl req -new -batch -subj "/C=DE/O=The TlsMate Company/CN=localhost Root CA RSA" -key private/root-ca-rsa.key -out csr/root-ca-rsa.csr
	${OPENSSLPATH}/openssl ca -batch -notext -selfsign -config root-ca.cnf -extensions root_ca_ext -days 3000 -in csr/root-ca-rsa.csr -out certs/root-ca-rsa.crt -keyfile private/root-ca-rsa.key

%-rsa.csr:
	${OPENSSLPATH}/openssl ca -batch -notext -config root-ca.cnf -extensions root_ca_ext -days 3000 -in csr/$*-rsa.csr -out certs/$*-rsa.crt -keyfile private/root-ca-rsa.key -cert certs/root-ca-rsa.crt
	cat certs/*.crt > certs/all-certs.pem
