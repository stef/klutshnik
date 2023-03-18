#!/bin/sh

cleanup() {
 kill $kms1 $kms2 $kms3 $kms4 $kms5
}

./kms 10000 config/ksm0.key config/auth.key &
kms1=$$

./kms 10001 config/ksm1.key config/auth.key &
kms2=$$

./kms 10002 config/ksm2.key config/auth.key &
kms3=$$

./kms 10003 config/ksm3.key config/auth.key &
kms4=$$

./kms 10004 config/ksm4.key config/auth.key &
kms5=$$

trap "cleanup" INT
