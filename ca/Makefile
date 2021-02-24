all: root-ca-rsa root-ca-ecdsa inter-ca-rsa inter-ca-ecdsa server client cafile install

clean:
	rm -f *.pem
	(cd server && make clean)
	(cd client && make clean)
	(cd inter-ca-rsa && make clean)
	(cd inter-ca-ecdsa && make clean)
	(cd root-ca-rsa && make clean)
	(cd root-ca-ecdsa && make clean)

root-ca-rsa:
	(cd root-ca-rsa && make all)

root-ca-ecdsa:
	(cd root-ca-ecdsa && make all)

inter-ca-rsa:
	(cd inter-ca-rsa && make all)

inter-ca-ecdsa:
	(cd inter-ca-ecdsa && make all)

server:
	(cd server && make all)

client:
	(cd client && make all)

cafile:
	cat root-ca-*/certs/*.crt > cafile.pem

install:
	cp inter-ca-rsa/crl/inter-ca-rsa.crl ../crl
	cp inter-ca-ecdsa/crl/inter-ca-ecdsa.crl ../crl

.PHONY: clean all root-ca-rsa root-ca-ecdsa inter-ca-rsa inter-ca-ecdsa server client cafile
