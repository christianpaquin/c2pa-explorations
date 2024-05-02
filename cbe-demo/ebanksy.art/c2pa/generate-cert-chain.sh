#!/bin/bash

# Generate certs for EBanksy

# This script generates 2-cert ECDSA chains (root -> signer).
# Leaf cert uses P-384 and is valid for 5 years,
# root CA uses P-521 and is valid for 10 years.

# directory where intermediate files are kept
tmpdir=tmp
mkdir -p "$tmpdir"

# generate self-signed root CA cert
openssl req -x509 -new -newkey ec:<(openssl ecparam -name secp521r1) -keyout "$tmpdir/ebanksy_root_CA.key" -out "$tmpdir/ebanksy_root_CA.crt" -nodes -subj "/CN=Ebanksy Art Root CA/O=Ebanksy Art" -days 3650 -config openssl_ca.cnf -extensions v3_ca -sha512

# generate signer cert request
openssl req -new -newkey ec:<(openssl ecparam -name secp384r1) -keyout "$tmpdir/ebanksy.key" -out "$tmpdir/ebanksy.csr" -nodes -subj "/CN=Ebanksy Art/O=Ebanksy Art" -config openssl_ca.cnf -extensions v3_signer -sha384

# root CA signs the signer cert request
openssl x509 -req -in "$tmpdir/ebanksy.csr" -out "$tmpdir/ebanksy.crt" -CA "$tmpdir/ebanksy_root_CA.crt" -CAkey "$tmpdir/ebanksy_root_CA.key" -CAcreateserial -days 1825 -extfile openssl_ca.cnf -extensions v3_signer -sha384
