# Verifiable Threshold Updatable Oblivious Key Management for Storage Systems

This is a PoC implementing the full VTUOKMS from

https://eprint.iacr.org/2019/1275
"Updatable Oblivious Key Management for Storage Systems"
by Stanislaw Jarecki, Hugo Krawczyk, and Jason Resch

This code depends on libsodium.

# example session

```
% ./client.py -c genkey -s :10000 :10001 :10002 :10003 :10004 -t 3
keyid 15ba5b105d1d50a4063ec43d3bece7c0

% echo "hello world" | ./client.py -c encrypt -k 15ba5b105d1d50a4063ec43d3bece7c0 >/tmp/encrypted

./client.py -c decrypt -s :10000 :10001 :10002 :10003 :10004 </tmp/encrypted >/tmp/decrypted && xxd /tmp/decrypted
00000000: 6865 6c6c 6f20 776f 726c 64              hello world

% ./client.py -c decrypt -s :10002 :10003 :10004 </tmp/encrypted >/tmp/decrypted && xxd /tmp/decrypted
00000000: 6865 6c6c 6f20 776f 726c 64              hello world

% echo -n /tmp/encrypted | ./client.py -c update -k 15ba5b105d1d50a4063ec43d3bece7c0 -s :10000 :10001 :10002 :10003 :10004

% ./client.py -c decrypt -s :10002 :10003 :10004 </tmp/encrypted >/tmp/decrypted && xxd /tmp/decrypted
00000000: 6865 6c6c 6f20 776f 726c 64              hello world
```
