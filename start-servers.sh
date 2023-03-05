#!/bin/sh

cleanup() {
 kill $kms1 $kms2 $kms3 $kms4 $kms5
}

./kms 10000 ksm0.key &
kms1=$$

./kms 10001 ksm1.key &
kms2=$$

./kms 10002 ksm2.key &
kms3=$$

./kms 10003 ksm3.key &
kms4=$$

./kms 10004 ksm4.key &
kms5=$$

trap "cleanup" INT
