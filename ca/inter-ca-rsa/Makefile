all: rsa

OPENSSLPATH ?= /usr/bin

clean:
	/bin/rm -rf certs private csr issuedcerts db crl

inter-ca-dirs:
	mkdir -p crl
	mkdir -p certs
	mkdir -p private
	mkdir -p csr
	mkdir -p issuedcerts
	mkdir -p db
	touch db/index
	${OPENSSLPATH}/openssl rand -hex 8 | awk '{print "0" $$0}' | sed 's/.$$//g' > db/serial
	echo 01 > db/crlnumber


cert/inter-ca-rsa.crt: inter-ca-dirs
	${OPENSSLPATH}/openssl genrsa -out private/inter-ca-rsa.key 2048
	${OPENSSLPATH}/openssl req -new -batch -subj "/C=DE/O=The TlsMate Company/CN=localhost intermediate CA RSA" -key private/inter-ca-rsa.key -out ../root-ca-rsa/csr/inter-ca-rsa.csr
	(cd ../root-ca-rsa && $($(MAKE)) inter-ca-rsa.csr)
	cp ../root-ca-rsa/certs/inter-ca-rsa.crt certs

%-rsa.csr:
	${OPENSSLPATH}/openssl ca -batch -notext -config inter-ca.cnf -extensions client_ext -days 3000 -in csr/$*-rsa.csr -out certs/$*-rsa.crt -keyfile private/inter-ca-rsa.key -cert certs/inter-ca-rsa.crt

%-dsa.csr:
	${OPENSSLPATH}/openssl ca -batch -notext -config inter-ca.cnf -extensions $*_ext -days 3000 -in csr/$*-dsa.csr -out certs/$*-dsa.crt -keyfile private/inter-ca-rsa.key -cert certs/inter-ca-rsa.crt

crl/inter-ca-rsa.crl.pem: certs/inter-ca-rsa.crt
	${OPENSSLPATH}/openssl ca -config inter-ca.cnf -gencrl -keyfile private/inter-ca-rsa.key -cert certs/inter-ca-rsa.crt -out crl/inter-ca-rsa.crl.pem
	${OPENSSLPATH}/openssl crl -inform PEM -in crl/inter-ca-rsa.crl.pem -outform DER -out crl/inter-ca-rsa.crl

rsa: cert/inter-ca-rsa.crt

crl: crl/inter-ca-rsa.crl.pem

revokation:
	${OPENSSLPATH}/openssl ca -revoke ./certs/server-revoked-rsa.crt -config inter-ca.cnf -crl_reason superseded -keyfile private/inter-ca-rsa.key -cert certs/inter-ca-rsa.crt
	$(MAKE) crl
