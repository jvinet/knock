#!/bin/bash

# This is sh script for otp section in knocks.conf like this:
# otp = AAgR%XXx30O$#, 45, 20000, on, tcp, tcp, tcp
function hash_hmac {
  digest="$1"
  data="$2"
  key="$3"
  shift 3

  a=`echo -n "$data" | openssl dgst "-$digest" -hmac "$key" "$@"`
  echo ${a: -40:40}
}


tme=`date '+%s'`
key="AAgR%XXx30O$#"
tm="45"
pr="20000"
host="knockd.example.com"

otp=$((tme/tm))

myip=`dig +short myip.opendns.com @resolver1.opendns.com`

res=$(hash_hmac "sha1" $otp $key)

echo tm = \'$otp\' key = \'$key\' hmac_sha1 = \'$res\'

port1=$(($((16#${res: 0:2}))+$pr))
port2=$(($((16#${res: 2:2}))+$pr))
port3=$(($((16#${res: 4:2}))+$pr))

nkey=$key$myip

res=$(hash_hmac "sha1" $otp $nkey)

echo key = \'$nkey\' hmac_sha1 = \'$res\'

port4=$(($((16#${res: 0:2}))+$pr))
port5=$(($((16#${res: 2:2}))+$pr))
port6=$(($((16#${res: 4:2}))+$pr))

echo port = $port1 or $port2 or $port3 or $port4 or $port5 or $port6


for p in $port1 $port2 $port3 $port4 $port5 $port6; do
  nmap -Pn --max-retries 0 -p $p $host >>/dev/null;
done



