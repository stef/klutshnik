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
printf "%s\n/tmp/klutshniked" "$delta" | klutshnik update

echo decrypt updated file
cat kltsk /tmp/klutshniked | klutshnik decrypt

echo list users
klutshnik listusers "keyid1" <kltsk

echo add user
xprt=$(klutshnik adduser keyid1 13lty/jQszJ1Xn5krTC2kltvPJDMqb4bqk3jgZxR430= update,decrypt <kltsk)

echo list users again
klutshnik listusers "keyid1" <kltsk

cd otherclient/
echo importing key to newly added user
klutshnik import "importedkey" "$xprt"

echo decrypt updated file with newly added user
klutshnik decrypt </tmp/klutshniked

echo rotate keyid1 with newly added user
out=$(klutshnik rotate "importedkey" | tr '\n' " ")
pk="${out%% *}"
delta="${out#* }"
echo "pk1    $pk"
echo "delta1 $delta"

echo update keyid1 encrypted file with delta from newly added user
printf "%s\n/tmp/klutshniked" "$delta" | klutshnik update

echo decrypt again updated file with newly added user
klutshnik decrypt </tmp/klutshniked

echo delete key by unauthorized newsly added user
klutshnik delete importedkey || true
cd ..

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
cat kltsk /tmp/klutshniked | klutshnik decrypt || true
