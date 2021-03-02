all: root-ca-rsa root-ca-ecdsa inter-ca-rsa inter-ca-ecdsa server client cafile crl install

clean:
	rm -f *.pem
	(cd server && $(MAKE) clean)
	(cd client && $(MAKE) clean)
	(cd inter-ca-rsa && $(MAKE) clean)
	(cd inter-ca-ecdsa && $(MAKE) clean)
	(cd root-ca-rsa && $(MAKE) clean)
	(cd root-ca-ecdsa && $(MAKE) clean)

root-ca-rsa:
	(cd root-ca-rsa && $(MAKE) all)

root-ca-ecdsa:
	(cd root-ca-ecdsa && $(MAKE) all)

inter-ca-rsa:
	(cd inter-ca-rsa && $(MAKE) all)

inter-ca-ecdsa:
	(cd inter-ca-ecdsa && $(MAKE) all)

server:
	(cd server && $(MAKE) all)

client:
	(cd client && $(MAKE) all)

cafile:
	cat root-ca-*/certs/*.crt > cafile.pem

crl:
	(cd inter-ca-rsa && $(MAKE) crl)

install:
	cp inter-ca-rsa/crl/inter-ca-rsa.crl ../crl
	cp inter-ca-ecdsa/crl/inter-ca-ecdsa.crl ../crl

.PHONY: clean all root-ca-rsa root-ca-ecdsa inter-ca-rsa inter-ca-ecdsa server client cafile
