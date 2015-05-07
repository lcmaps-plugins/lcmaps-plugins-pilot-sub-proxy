#!/bin/sh
BITS=rsa:1024
HASH=sha256

if [ $# -lt 1 ];then
    echo "Usage: $(basename $0) <CN value> [payload proxyfile]" >&2
    exit 1
fi

# Input proxy
X509_USER_PROXY=${X509_USER_PROXY:-/tmp/x509up_u$(id -u)}

# Subject of payload proxy
PROXY_CN="/CN=$1"

# Output filename
if [ -z "$2" ];then
    PROXY_FILE=${X509_USER_PROXY}_payload
else
    PROXY_FILE=$2
fi

########################################################################

# Set nameopts for getting subject from proxy
NAMEOPTS="esc_2253,esc_ctrl,utf8,dump_nostr,dump_der,sep_multiline,sname"

# New serial number
SERIAL=`expr $RANDOM \* $RANDOM`

# Different tempfiles
OPENSSL_CONF=`mktemp openssl.cnf.XXXXXX`
PROXYREQ=`mktemp proxyrequest.XXXXXX`
PROXYKEY=`mktemp proxykey.XXXXXX`
PROXYCERT=`mktemp proxycert.XXXXXX`
LOGFILE=`mktemp logfile.XXXXXX`

cleanup()   {
    for f in "$OPENSSL_CONF" "$PROXYREQ" "$PROXYKEY" "$PROXYCERT" "$LOGFILE";do
	if [ -n "$f" -a -f "$f" ];then
	    rm "$f"
	fi
    done
}

# Create OpenSSL config file on the fly. Need RFC compliant limited proxy with
# proxy-path-length 0 (no more proxy delegations allowed).
cat > $OPENSSL_CONF << EOF
extensions = rfc3820_proxy

[ rfc3820_proxy ]
keyUsage = critical,digitalSignature,keyEncipherment
1.3.6.1.5.5.7.1.14 = critical,ASN1:SEQUENCE:rfc3820_seq_sect

[ rfc3820_seq_sect ]
field1 = INTEGER:0
field2 = SEQUENCE:limited_policy

[ limited_policy ]
p1 = OID:1.3.6.1.4.1.3536.1.1.1.9
EOF

# Get subject from input proxy
SUBJ=$(openssl x509 -in $X509_USER_PROXY -noout -subject -nameopt $NAMEOPTS|\
       sed '1d;s:^ *:/:'|tr -d '\n')
if [ -z "$SUBJ" ];then
    echo "Getting subject of $X509_USER_PROXY failed" >&2
    cleanup
    exit 1
fi

openssl req \
    -new -nodes -newkey $BITS -subj "${SUBJ}${PROXY_CN}" \
    -keyout $PROXYKEY -out $PROXYREQ 2> $LOGFILE || {
	echo "Creating request failed" >&2
	cat $LOGFILE >&2
	cleanup
	exit 1
    }


openssl x509 \
    -req -CAkeyform pem -in $PROXYREQ -out $PROXYCERT \
    -CA $X509_USER_PROXY -CAkey $X509_USER_PROXY \
    -set_serial $SERIAL -days 1 -$HASH \
    -extfile $OPENSSL_CONF 2> $LOGFILE || {
	echo "Signing request failed" >&2
	cat $LOGFILE >&2
	cleanup
	exit 1
    }

# Add new cert and key to proxy file
cat $PROXYCERT $PROXYKEY > $PROXY_FILE

# Append certificate only parts of input proxy
doprint=0
cat $X509_USER_PROXY | while read line ; do
    if [ "$line" = "-----BEGIN CERTIFICATE-----" ];then
	echo "$line"
	doprint=1
    elif [ "$line" = "-----END CERTIFICATE-----" ];then
	echo "$line"
	doprint=0
    elif [ $doprint -eq 1 ];then
	echo "$line"
    fi
done >> $PROXY_FILE

# Cleanup temp files
cleanup

echo "Proxy is left in $PROXY_FILE"
