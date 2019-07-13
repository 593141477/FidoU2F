#!/bin/bash

#self-sign
CAkeyname=attestation

keyname=attestation
curve=prime256v1

if [[ -f "$keyname".pem ]] ;then
    echo "Key already exists"
else
    # generate EC private key
    openssl ecparam -genkey -name "$curve" -out "$keyname".pem
fi
if [[ -f "$keyname".der ]] ;then
    true
else
    # generate a "signing request"
    openssl req -new -key "$keyname".pem -out "$keyname".csr
    # self sign the request
    openssl x509 -req -sha256 -in "$keyname".csr -signkey "$CAkeyname".pem -outform DER -out "$keyname".der

    # openssl ec -in "$keyname".pem -pubout -out "$keyname".pub.pem
    # ./signcert "$CAkeyname".pem "$keyname".pub.pem "$keyname".der
    rm "$keyname".csr
fi

size=$(wc "$keyname".der |awk '{printf("%04x\n",$3)}')
priv=$(openssl ec -in "$keyname".pem -text | grep -A 3 'priv:'|tail -n 3|tr -d -C '[:alnum:]')

java -jar gp.jar --delete A0000006472F00
java -jar gp.jar --install FidoU2F.cap --params "$size" &&
python load_cert.py "$keyname".der &&
java -jar gp.jar -a 00a4040008A0000006472F0001 -a "8002000020$priv" &&
rm -Ir "$keyname".der "$keyname".pem
