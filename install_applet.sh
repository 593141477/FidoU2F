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
fi

eval $(stat -s "$keyname".der)
size=$(printf '%04x' "$st_size")
priv=$(openssl ec -in "$keyname".pem -text | grep -A 3 'priv:'|tail -n 3|tr -d -C '[:alnum:]'|sed 's/..//')

# java -jar gp.jar --delete A000000647004F97A2E95001
# java -jar gp.jar --install ledger-u2f.cap --params "01$size$priv"

java -jar gp.jar --delete A0000006472F00
java -jar gp.jar --install u2ftoken.cap --params "$size" &&
python load_cert.py "$keyname".der &&
java -jar gp.jar -a 00a4040008A0000006472F0001 -a "8002000020$priv" &&
rm "$keyname".der "$keyname".pem
