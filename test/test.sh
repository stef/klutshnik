#!/bin/sh -e

echo create keyid1
pk=$(klutshnik create "keyid1" <kltsk)
echo "pk $pk"

echo encrypt attack at dawn for keyid1
echo "attack at dawn" | klutshnik encrypt "$pk" >/tmp/klutshniked

echo decrypt
cat kltsk /tmp/klutshniked | klutshnik decrypt

echo rotate keyid1
out=$(klutshnik rotate "keyid1" <kltsk | tr '\n' " ")
pk="${out%% *}"
delta="${out#* }"

echo "pk1    $pk"
echo "delta1 $delta"
echo update keyid1 encrypted file with delta
printf "%s\n/tmp/klutshniked" "$delta" | klutshnik update keyid1

echo decrypt updated file
cat kltsk /tmp/klutshniked | klutshnik decrypt

echo list users
klutshnik listusers "keyid1" <kltsk

echo add user
klutshnik adduser keyid1 13lty/jQszJ1Xn5krTC2kltvPJDMqb4bqk3jgZxR430= update <kltsk

echo list users again
klutshnik listusers "keyid1" <kltsk

cd otherclient/
cp ../keystore/* keystore/
echo decrypt updated file with newly added unauthorized user
klutshnik decrypt </tmp/klutshniked || true

echo rotate keyid1 with newly added user
out=$(klutshnik rotate "keyid1" | tr '\n' " ")
pk="${out%% *}"
delta="${out#* }"
echo "pk1    $pk"
echo "delta1 $delta"
cd ..

echo update keyid1 encrypted file with delta from newly added user
printf "%s\n/tmp/klutshniked" "$delta" | klutshnik update keyid1

echo decrypt updated file
cat kltsk /tmp/klutshniked | klutshnik decrypt || true

echo refresh key meta
klutshnik refresh keyid1 <kltsk

echo refresh key meta again
klutshnik refresh keyid1 <kltsk

echo decrypt updated file
cat kltsk /tmp/klutshniked | klutshnik decrypt

echo del added user
klutshnik deluser keyid1 13lty/jQszJ1Xn5krTC2kltvPJDMqb4bqk3jgZxR430= <kltsk

echo list users after delete
klutshnik listusers "keyid1" <kltsk

echo delete key keyid1
klutshnik delete "keyid1" <kltsk

echo trying to decrypt with non-existing key
cat kltsk /tmp/klutshniked | klutshnik decrypt
