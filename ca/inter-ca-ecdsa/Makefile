all: ecdsa crl

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


cert/inter-ca-ecdsa.crt: inter-ca-dirs
	${OPENSSLPATH}/openssl ecparam -name prime256v1 -genkey -out private/inter-ca-ecdsa.key
	${OPENSSLPATH}/openssl req -new -batch -subj "/C=DE/O=The TlsMate Company/CN=localhost intermediate CA ECDSA" -key private/inter-ca-ecdsa.key -out ../root-ca-ecdsa/csr/inter-ca-ecdsa.csr
	(cd ../root-ca-ecdsa && $(MAKE) inter-ca-ecdsa.csr)
	cp ../root-ca-ecdsa/certs/inter-ca-ecdsa.crt certs

%-ecdsa.csr:
	${OPENSSLPATH}/openssl ca -batch -notext -config inter-ca.cnf -extensions server_ext -days 3000 -in csr/$*-ecdsa.csr -out certs/$*-ecdsa.crt -keyfile private/inter-ca-ecdsa.key -cert certs/inter-ca-ecdsa.crt

%-ed25519.csr:
	${OPENSSLPATH}/openssl ca -batch -notext -config inter-ca.cnf -extensions server_ext -days 3000 -in csr/$*-ed25519.csr -out certs/$*-ed25519.crt -keyfile private/inter-ca-ecdsa.key -cert certs/inter-ca-ecdsa.crt

%-ed448.csr:
	${OPENSSLPATH}/openssl ca -batch -notext -config inter-ca.cnf -extensions server_ext -days 3000 -in csr/$*-ed448.csr -out certs/$*-ed448.crt -keyfile private/inter-ca-ecdsa.key -cert certs/inter-ca-ecdsa.crt

crl/inter-ca-ecdsa.crl.pem: certs/inter-ca-ecdsa.crt
	${OPENSSLPATH}/openssl ca -config inter-ca.cnf -gencrl -keyfile private/inter-ca-ecdsa.key -cert certs/inter-ca-ecdsa.crt -out crl/inter-ca-ecdsa.crl.pem
	${OPENSSLPATH}/openssl crl -inform PEM -in crl/inter-ca-ecdsa.crl.pem -outform DER -out crl/inter-ca-ecdsa.crl

ecdsa: cert/inter-ca-ecdsa.crt

crl: crl/inter-ca-ecdsa.crl.pem
