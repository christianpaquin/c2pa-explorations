#!/bin/bash
# This script generates 3-cert ECDSA chains (root -> CA -> signer).
# Leaf cert uses P-256 and is valid for 1 year,
# CA and root CA use the increasingly stronger P-384 and P-521, and are valid for
# 5 and 10 years, respectively.
# The script also generate a self-signed cert from an "unknown" signer

# directory where intermediate files are kept
tmpdir=certs
mkdir -p "$tmpdir"

#
# Valid Origin test certs
#

# generate self-signed root CA cert
openssl req -x509 -new -newkey ec:<(openssl ecparam -name secp521r1) -keyout "$tmpdir/root_CA.key" -out "$tmpdir/root_CA.crt" -nodes -subj "/CN=Project Origin Test Root CA" -days 3650 -config openssl_ca.cnf -extensions v3_ca -sha512

# generate intermediate CA cert request
openssl req -new -newkey ec:<(openssl ecparam -name secp384r1) -keyout "$tmpdir/CA.key" -out "$tmpdir/CA.csr" -nodes -subj "/CN=Project Origin Test CA" -config openssl_ca.cnf -extensions v3_ca -sha384

# root CA signs the CA cert request
openssl x509 -req -in "$tmpdir/CA.csr" -out "$tmpdir/CA.crt" -CA "$tmpdir/root_CA.crt" -CAkey "$tmpdir/root_CA.key" -CAcreateserial -days 1825 -extfile openssl_ca.cnf -extensions v3_ca -sha512

# generate signer cert request
openssl req -new -newkey ec:<(openssl ecparam -name prime256v1) -keyout "$tmpdir/c2pa.key" -out "$tmpdir/c2pa.csr" -nodes -subj "/CN=C2PA Web Domain Anchoring Demo" -config openssl_ca.cnf -extensions v3_signer -sha256

# intermediate CA signs the issuer cert request
openssl x509 -req -in "$tmpdir/c2pa.csr" -out "$tmpdir/c2pa.crt" -CA "$tmpdir/CA.crt" -CAkey "$tmpdir/CA.key" -CAcreateserial -days 365 -extfile openssl_ca.cnf -extensions v3_signer -sha384

# TODO: needed?
cat "$tmpdir/c2pa.crt" "$tmpdir/CA.crt" "$tmpdir/root_CA.crt" > "$tmpdir/chain.pem"

# add the issuer key to the JWK sets
node certs-to-x5c.js --key "$tmpdir/c2pa.key" --cert "$tmpdir/c2pa.crt" --cert "$tmpdir/CA.crt" --cert "$tmpdir/root_CA.crt" --private "c2pa.private.json" --public "c2pa.json"