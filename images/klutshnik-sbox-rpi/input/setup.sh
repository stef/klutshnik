#!/bin/sh -e

if [ -f /etc/klutshnikd/initialized ]; then
	return 0
fi

set -x
exec >/data/klutshnik/setup.log 2>&1

logger -t "rc.klutshnik-setup" "Setting up klutshnik"

sed  "s/some natrium-chloride and some chilli/$(dd if=/dev/random bs=1 count=32 2>/dev/null | base32)/" </data/klutshnik/klutshnik.cfg_template >/etc/klutshnikd/config
openssl ecparam -genkey -out /etc/klutshnikd/key.pem -name secp384r1
openssl req -new -nodes -x509 -sha256 -key /etc/klutshnikd/key.pem -out /etc/klutshnikd/cert.pem -days 365 -subj '/CN=klutshnik-rpi'
chown klutshnik /etc/klutshnikd/cert.pem /etc/klutshnikd/key.pem

while read line; do
   case "$line" in
      successfully\ created\ long-term\ signature\ key\ pair*) read _; read _; read _;  read _; read ltsigpub;;
      successfully\ created\ long-term\ noise\ key\ pair*) read _; read _; read _; read _; read noisepub;;
      The\ following\ are\ the\ base64\ encoded\ long-term\ and\ noise\ public\ key*) read authuser;;
   esac
done <<EOF
$(klutshnikd init 2>&1)
EOF

chown klutshnik:klutshnik /etc/klutshnikd/ltsig.key
chown klutshnik:klutshnik /etc/klutshnikd/ltsig.key.pub
chown klutshnik:klutshnik /etc/klutshnikd/noise.key
chown klutshnik:klutshnik /etc/klutshnikd/noise.key.pub

echo $authuser >>/etc/klutshnikd/authorized_keys
chown klutshnik:klutshnik /etc/klutshnikd/authorized_keys

mount -o remount,rw /
# set up tor

echo "HiddenServiceDir /var/lib/tor/klutshnik/" >>/etc/tor/torrc
echo "HiddenServicePort 443 127.0.0.1:2323" >>/etc/tor/torrc
/etc/init.d/tor start
while [ ! -f /var/lib/tor/klutshnik/hostname ]; do
   sleep 1
done
/etc/init.d/tor stop

cat >/etc/motd <<EOT
Welcome to your Klutshnik v$(cat /data/klutshnik/klutshnik-rev) raspberry pi device

Share this with all the users/clients that should have access to this klutshnik
server:
    ltsigkey="$ltsigpub"

Set the following in all other klutshnik servers authorized_keys file which
should be part of the same threshold setup:
    $authuser

Store this Self-signed TLS cert in your clients config and point the servers
stanza "ssl_cert" to this file, if you want a real cert, we have acme.sh,
acme-tiny and certbot pre-installed:
$(sed 's/^/\t/' /etc/klutshnikd/cert.pem)

Don't forget to set your ~/.ssh/authorized_keys and disable password logins in
/etc/ssh/sshd_config

If you want you can enable tor by running
    rc-update add tor default; /etc/init.d/tor start
and it will serve klutshnik as a hidden service on the hostname:
    $(cat /var/lib/tor/klutshnik/hostname).
EOT

cd /data/klutshnik
source env/bin/activate

{ cat test/servers/authorized_keys_template; echo $authuser; } >test/servers/authorized_keys
cp test/servers/authorized_keys /etc/klutshnikd/authorized_keys

killall klutshnikd || true
su klutshnik -c 'strace -I1 --kill-on-exit -fo /data/klutshnik/strace.log /usr/bin/klutshnikd >/data/klutshnik/log 2>/data/klutshnik/err' &
straced_pid=$!

cd test/servers
rm -rf */data/[0-9a-f]* || true
ORACLE=/usr/bin/klutshnikd ./start-servers.sh &
servers_pid=$!

cd ..
rm -rf keystore/[0-9a-f]* otherclient/keystore/[0-9a-f]* || true
./test.sh
kill ${servers_pid} $straced_pid
cd ..

minijail/tools/generate_seccomp_policy.py strace.log >klutshnikd.seccomp
minijail/tools/compile_seccomp_policy.py klutshnikd.seccomp /etc/klutshnikd/klutshnikd.bpf

echo $authuser >/etc/klutshnikd/authorized_keys

# clean up

rm -rf /usr/lib/liboprf.so /usr/lib/liboprf.a \
   /usr/lib/liboprf-noiseXK.so /usr/lib/liboprf-noiseXK.a \
   /usr/include/oprf

rm -rf /usr/lib/libklutshnik.so /usr/lib/libklutshnik.a \
   /usr/lib/pkgconfig/libklutshnik.pc /usr/include/klutshnik

mount -o remount,ro /

rm -rf /data/klutshnik/klutshnik
rm -rf /data/klutshnik/liboprf
rm -rf /data/klutshnik/env
rm -rf /data/klutshnik/test
rm -rf /data/klutshnik/minijail

# allow access via port 443
iptables -t nat -A PREROUTING -p tcp --dport 443 -j REDIRECT --to-port 2323
/etc/init.d/iptables save
rc-update add iptables default

touch /etc/klutshnikd/initialized
