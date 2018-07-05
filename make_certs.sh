#!/bin/sh

# OpenSSL configuration
CERTDIR=./priv/test_certs
CADIR=$CERTDIR/ca

[ -d $CERTDIR ] || mkdir -p $CERTDIR
[ -d $CADIR ] || mkdir $CADIR
[ -d $CADIR/ca.db.certs ] || mkdir $CADIR/ca.db.certs
touch $CADIR/ca.db.index
echo 01 > $CADIR/ca.db.serial

cat>$CADIR/ca.conf<<'EOF'
[ ca ]
default_ca = ca_default

[ ca_default ]
dir = REPLACE_LATER
certs = $dir
new_certs_dir = $dir/ca.db.certs
database = $dir/ca.db.index
serial = $dir/ca.db.serial
RANDFILE = $dir/ca.db.rand
certificate = $dir/ca.pem
private_key = $dir/ca.key
default_days = 365
default_crl_days = 30
default_md = md5
preserve = no
policy = generic_policy
[ generic_policy ]
countryName = optional
stateOrProvinceName = optional
localityName = optional
organizationName = optional
organizationalUnitName = optional
commonName = supplied
emailAddress = optional
EOF
sed -i "s|REPLACE_LATER|${CADIR}|" ${CADIR}/ca.conf

# CA
openssl genrsa -out $CERTDIR/test_ca.key 2048
openssl req -x509 -new -key $CERTDIR/test_ca.key -days 36500 -out $CERTDIR/test_ca.pem -subj "/C=RU/ST=Default-City/L=DC/O=Periscope/CN=Periscope Test CA"

SERVERHOST=${1:-localhost}

# Server certificate
openssl req -new -newkey rsa:2048 -keyout $CERTDIR/test_server.key -nodes -out $CERTDIR/test_server.csr -subj "/C=RU/ST=Default-City/L=DC/O=Periscope/CN=$SERVERHOST"
openssl ca -batch -config $CADIR/ca.conf -days 36500 -in $CERTDIR/test_server.csr -out $CERTDIR/test_server.crt -cert $CERTDIR/test_ca.pem -keyfile $CERTDIR/test_ca.key
cat $CERTDIR/test_server.crt $CERTDIR/test_server.key > $CERTDIR/test_server.pem

# Client certificate (CA signed)
openssl req -new -newkey rsa:2048 -keyout $CERTDIR/test_client_ca.key -nodes -out $CERTDIR/test_client_ca.csr -subj "/C=RU/ST=Default-City/L=DC/O=Periscope/CN=Periscope Test Client (CA)"
openssl ca -batch -config $CADIR/ca.conf -days 36500 -in $CERTDIR/test_client_ca.csr -out $CERTDIR/test_client_ca.crt -cert $CERTDIR/test_ca.pem -keyfile $CERTDIR/test_ca.key
cat $CERTDIR/test_client_ca.crt $CERTDIR/test_client_ca.key > $CERTDIR/test_client_ca.pem

# Client certificate (no CA)
openssl req -new -newkey rsa:2048 -keyout $CERTDIR/test_client.key -nodes -out $CERTDIR/test_client.csr -subj "/C=RU/ST=Default-City/L=DC/O=Periscope/CN=Periscope Test Client"
cat $CERTDIR/test_client.crt $CERTDIR/test_client.key > $CERTDIR/test_client.pem

rm -rf $CADIR
