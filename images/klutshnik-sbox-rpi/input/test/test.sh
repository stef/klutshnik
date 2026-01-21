#!/bin/sh -e

doinit=/bin/false

while [ "$#" -gt 0 ]; do
    arg="$1"
    case "$arg" in
        /dev/tty*) devicetty="$arg" ;;
        init) doinit=/bin/true ;;
        *) echo "unknown param: $arg"; exit 1;;
    esac
    shift
done

if $doinit; then
   echo cleanup
   rm -rf client.key keystore
   cp k.cfg klutshnik.cfg
   
   echo init
   out=$(klutshnik init 2>/dev/null ./klutshnik.cfg)
   authkey=$(echo "$out" | grep -F KLTFCPK-)
   echo "authkey $authkey"
   cpk=$(echo "$out" | grep -F KLTFSPK-)
   echo "cpk $cpk"
   { echo -n kltsk- ; base64 -w0 <client.key ; } >kltsk
   sed -i -e 's/clientkey_path="client.key"/#clientkey_path="client.key"/' klutshnik.cfg
   if [ -n "$devicetty"  ]; then
      echo setting auth key in device at "$devicetty"
   fi
fi

echo create keyid1
pk=$(klutshnik create "keyid1" <kltsk)
echo "pk $pk"
sleep 1

echo encrypt attack at dawn for keyid1
echo "attack at dawn" | klutshnik encrypt "$pk" >/tmp/klutshniked
sleep 1

echo decrypt
cat kltsk /tmp/klutshniked | klutshnik decrypt
sleep 1

echo rotate keyid1
out=$(klutshnik rotate "keyid1" <kltsk | tr '\n' " ")
pk="${out%% *}"
delta="${out#* }"
sleep 1

echo "pk1    $pk"
echo "delta1 $delta"
echo update keyid1 encrypted file with delta
printf "%s\n/tmp/klutshniked" "$delta" | klutshnik update
sleep 1

echo decrypt updated file
cat kltsk /tmp/klutshniked | klutshnik decrypt
sleep 1

echo list users
klutshnik listusers "keyid1" <kltsk
sleep 1

cd otherclient

if $doinit; then
   echo cleanup otherclient
   rm -rf client.key keystore
   cp k.cfg klutshnik.cfg
   
   echo init otherclient
   out=$(klutshnik init 2>/dev/null ./klutshnik.cfg)
sleep 1
   oc_authkey=$(echo "$out" | grep -F KLTFCPK-)
   oc_cpk=$(echo "$out" | grep -F KLTFSPK-)
   if [ -n "$devicetty" ]; then
      echo setting auth key in device at "$devicetty"
   fi
else
   oc_cpk=$(yq -o toml -p toml '.client.ltsigpub' klutshnik.cfg)
   oc_cpk="KLTFSPK-${oc_cpk##LTSIGPK-}"
   oc_noisekey=$(yq -o toml -p toml '.client.noisepub' klutshnik.cfg)
   oc_authkey=$({ echo ${oc_cpk##KLTFSPK-} | base64 -d ; echo ${oc_noisekey##NOISEPK-} | base64 -d ; } | base64 -w 90)
fi

cd ..

echo add user otherclient ${oc_authkey}
xprt=$(klutshnik adduser keyid1 ${oc_authkey} update,decrypt <kltsk)
sleep 1

echo list users again
klutshnik listusers "keyid1" <kltsk
sleep 1

cd otherclient/
echo importing key to newly added user
echo klutshnik import "importedkey" "$xprt"
klutshnik import "importedkey" "$xprt"
sleep 1

echo decrypt updated file with newly added user
klutshnik decrypt </tmp/klutshniked
sleep 1

echo rotate keyid1 with newly added user
out=$(klutshnik rotate "importedkey" | tr '\n' " ")
sleep 1
pk="${out%% *}"
delta="${out#* }"
echo "pk1    $pk"
echo "delta1 $delta"

echo update keyid1 encrypted file with delta from newly added user
printf "%s\n/tmp/klutshniked" "$delta" | klutshnik update
sleep 1

echo decrypt again updated file with newly added user
klutshnik decrypt </tmp/klutshniked
sleep 1

echo delete key by unauthorized newly added user
klutshnik delete importedkey || true
sleep 1
cd ..

sleep 1 # due to fail the device reboots
echo decrypt updated file
cat kltsk /tmp/klutshniked | klutshnik decrypt || true
sleep 1

sleep 1 # due to fail the device reboots
echo refresh key meta
klutshnik refresh keyid1 <kltsk
sleep 1

echo refresh key meta again
klutshnik refresh keyid1 <kltsk
sleep 1

echo decrypt updated file
cat kltsk /tmp/klutshniked | klutshnik decrypt
sleep 1

echo del added user
klutshnik deluser keyid1 ${oc_authkey} <kltsk
sleep 1

echo list users after delete
klutshnik listusers "keyid1" <kltsk
sleep 1

echo delete key keyid1
klutshnik delete "keyid1" <kltsk
sleep 1

echo trying to decrypt with non-existing key
cat kltsk /tmp/klutshniked | klutshnik decrypt || true
