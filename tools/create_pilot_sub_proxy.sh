#!/bin/sh
#
# Copyright (c) FOM-Nikhef 2015-
# 
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Authors:
# 2015-
#    Mischa Sall\'e <msalle@nikhef.nl>
#    NIKHEF Amsterdam, the Netherlands
#    <grid-mw-security@nikhef.nl>
#

# cmdline adaptable defaults:
VERB=0
PROXY_CN=""
user=""
PREFIX="user:"
X509_USER_PROXY=${X509_USER_PROXY:-/tmp/x509up_u$(id -u)}
PROXY_FILE=${X509_USER_PROXY}_payload

# Other defaults:
BITS=1024				# RSA keylength
HASH=sha256				# hash algorithm

# Programs
OD=$(which od)
TR=$(which tr)
RM=$(which rm)
CAT=$(which cat)
SED=$(which sed)
MKTEMP=$(which mktemp)
BASENAME=$(which basename)
OPENSSL=$(which openssl)

# Script name
prog=$($BASENAME $0)

########################################################################

# Usage function
usage()	{
    echo "Usage: $($BASENAME $0) <options>"
    echo "Options:"
    echo " -h             print this help text"
    echo " -v             be verbose"
    echo " -c <cn-value>  CN value (prefix+username), added after \"/CN=\""
    echo " -u <user>      username, added after \"/CN=${PREFIX}\""
    echo " -P <prefix>    prefix in /CN field, default: \"$PREFIX\""
    echo " -x <proxy>     pilot proxy filename, default: \"$X509_USER_PROXY\""
    echo " -p <proxy>     payload proxy filename, default: \"$PROXY_FILE\""
    exit 0
}

# Called for invalid options
illoption() {
    case $1 in
        :)  echo "$prog: option \`-$2' requires an argument" >&2 ;;
        ?)  echo "$prog: invalid option -- $2" >&2 ;;
    esac
    echo "Try \`$prog -h' for more information" >&2
    exit $3
}

# Verbose log
verb()	{
    if [ $VERB -eq 1 ];then
	echo "$*"
    fi
}

# Get command line options
while getopts ":hvc:u:P:x:p:" i "$@";do
    case $i in
	h)  usage ;;
	v)  VERB=1 ;;
	c)  PROXY_CN="$OPTARG" ;;
	u)  user="$OPTARG" ;;
	P)  PREFIX="$OPTARG" ;;
	x)  X509_USER_PROXY="$OPTARG" ;;
	p)  PROXY_FILE="$OPTARG" ;;
	:)  illoption $i "$OPTARG" 2 ;;
	?)  illoption $i "$OPTARG" 2 ;;
    esac
done

# Check mandatory arguments
if [ -z "$PROXY_CN" ];then
    if [ -z "$user" ];then
	echo "$prog: Missing mandatory option -u <user> or -c <proxy-cn>" >&2
	echo "Try \`$prog -h' for more information" >&2
	exit 1
    fi

    # Subject of payload proxy
    PROXY_CN="${PREFIX}$user"
fi

# Set nameopts for getting subject from proxy
NAMEOPTS="esc_2253,esc_ctrl,utf8,dump_nostr,dump_der,sep_multiline,sname"

# New serial number: use 4 random bytes
SERIAL=$($OPENSSL rand 4|$OD -t u4 -A n|$TR -d '[:space:]')

# Enforce umask
umask 077

# Different tempfiles: put in separate directory in $TMPDIR or /tmp
PROXYTMPDIR=$($MKTEMP -d --tmpdir create_pusp_XXXXXX)
OPENSSL_CONF=$($MKTEMP --tmpdir=$PROXYTMPDIR openssl.cnf.XXXXXX)
PROXYREQ=$($MKTEMP --tmpdir=$PROXYTMPDIR proxyrequest.XXXXXX)
PROXYKEY=$($MKTEMP --tmpdir=$PROXYTMPDIR proxykey.XXXXXX)
PROXYCERT=$($MKTEMP --tmpdir=$PROXYTMPDIR proxycert.XXXXXX)
LOGFILE=$($MKTEMP --tmpdir=$PROXYTMPDIR logfile.XXXXXX)

cleanup()   {
    # Don't do a $RM -rf for safety 
    for f in "$OPENSSL_CONF" "$PROXYREQ" "$PROXYKEY" "$PROXYCERT" "$LOGFILE";do
	if [ -n "$f" -a -f "$f" ];then
	    $RM "$f"
	fi
    done
    rmdir $PROXYTMPDIR || {
	echo "Cleanup of $PROXYTMPDIR failed" >&2
    }
}

myexit()    {
    cleanup
    exit $1
}

# Create OpenSSL config file on the fly. Need RFC compliant limited proxy with
# proxy-path-length 0 (no more proxy delegations allowed).
$CAT > $OPENSSL_CONF << EOF
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
SUBJ=$($OPENSSL x509 -in $X509_USER_PROXY -noout -subject -nameopt $NAMEOPTS|\
       $SED 's+/+\\/+g'|$SED '1d;s:^ *:/:'|$TR -d '\n')
if [ -z "$SUBJ" ];then
    echo "Getting subject of $X509_USER_PROXY failed" >&2
    myexit 1
fi
verb "Got subject \"$SUBJ\""

# Create certificate signing request
verb "Generating $BITS bits RSA key and request for \"${PROXY_CN}\""
$OPENSSL req \
    -utf8 -new -nodes -newkey rsa:$BITS -subj "${SUBJ}/CN=${PROXY_CN}" \
    -keyout $PROXYKEY -out $PROXYREQ 2> $LOGFILE || {
	echo "Creating request failed, logfile:" >&2
	$CAT $LOGFILE >&2
	myexit 1
    }

# Sign certificate signing request, creating proxy certificate
verb "Signing key and request to create proxy cert"
$OPENSSL x509 \
    -req -CAkeyform pem -in $PROXYREQ -out $PROXYCERT \
    -CA $X509_USER_PROXY -CAkey $X509_USER_PROXY \
    -set_serial $SERIAL -days 1 -$HASH \
    -extfile $OPENSSL_CONF 2> $LOGFILE || {
	echo "Signing request failed, logfile:" >&2
	$CAT $LOGFILE >&2
	myexit 1
    }

# Add new cert and key to proxy file
$CAT $PROXYCERT $PROXYKEY > $PROXY_FILE

# Append certificate only parts of input proxy
doprint=0
$CAT $X509_USER_PROXY | while read line ; do
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

verb "Proxy is left in $PROXY_FILE"
