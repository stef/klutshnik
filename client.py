#!/usr/bin/env python
# SPDX-FileCopyrightText: 2023, Marsiske Stefan
# SPDX-License-Identifier: GPL-3.0-or-later


import os, io, sys, socket, struct, select
import ctypes, ctypes.util, tomllib
import pysodium, argparse
from binascii import unhexlify

kmslib = ctypes.cdll.LoadLibrary(ctypes.util.find_library('kms') or
                                 ctypes.util.find_library('libkms.so') or
                                 ctypes.util.find_library('libkms') or
                                 ctypes.util.find_library('libkms0'))
if not kmslib._name:
   raise ValueError('Unable to find libkms')

VERSION=0
DKG = 1
Evaluate  = 2
TUOKMS_Update = 3

KEYID_SIZE = 16

def read_pkt(s,size):
   res = []
   read = 0
   while read<size or len(res[-1])==0:
     res.append(s.recv(size-read))
     read+=len(res[-1])
   return b''.join(res)

def split_by_n(obj, n):
  # src https://stackoverflow.com/questions/9475241/split-string-every-nth-character
  return [obj[i:i+n] for i in range(0, len(obj), n)]

def connect(servers):
   conns = []
   for host,port in servers:
       fd = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
       conns.append(fd)
       conns[-1].settimeout(15)
       conns[-1].connect((host, port))
   return conns

def gather(conns, expectedmsglen, n, proc=None):
   responses={}
   while len(responses)!=n:
      r, _,_ =select.select(conns,[],[],5)
      if not r: sys.exit(1)
      for fd in r:
         idx = conns.index(fd)
         if idx in responses:
            continue
         pkt = read_pkt(fd, expectedmsglen)
         responses[idx]=pkt if not proc else proc(pkt)
   return responses

def dkg(servers,threshold):
   n = len(servers)
   keyid = pysodium.randombytes(KEYID_SIZE)
   conns = connect(servers)

   for index,c in enumerate(conns):
       msg = b"%c%c%c%c%c%s" % (VERSION, DKG, index+1, threshold, n, keyid)
       msg = struct.pack("H", len(msg)) + msg
       c.sendall(msg)

   responders=gather(conns, (pysodium.crypto_core_ristretto255_BYTES * threshold) + (33*n*2), n, lambda x: (x[:threshold*pysodium.crypto_core_ristretto255_BYTES], split_by_n(x[threshold*pysodium.crypto_core_ristretto255_BYTES:], 2*33)) )

   commitments = b''.join(responders[i][0] for i in range(n))
   for i in range(n):
       shares = b''.join([responders[j][1][i] for j in range(n)])
       msg = commitments + shares
       conns[i].sendall(msg)

   oks = gather(conns, 66, n)

   shares = b''.join(oks[i] for i in range(n))
   yc = ctypes.create_string_buffer(pysodium.crypto_core_ristretto255_BYTES)
   kmslib.tuokms_pubkey(n, threshold, shares, yc)
   return yc.raw, keyid

def encrypt(plaintext, yc):
   w = ctypes.create_string_buffer(pysodium.crypto_core_ristretto255_BYTES)
   ciphertext=ctypes.create_string_buffer(len(plaintext)+pysodium.crypto_secretbox_NONCEBYTES+pysodium.crypto_secretbox_MACBYTES)
   kmslib.uokms_encrypt(yc, plaintext, len(plaintext), w, ciphertext)
   return w.raw, ciphertext.raw

def blind(w):
   r = ctypes.create_string_buffer(pysodium.crypto_core_ristretto255_SCALARBYTES)
   c = ctypes.create_string_buffer(pysodium.crypto_core_ristretto255_SCALARBYTES)
   d = ctypes.create_string_buffer(pysodium.crypto_core_ristretto255_SCALARBYTES)
   a = ctypes.create_string_buffer(pysodium.crypto_core_ristretto255_BYTES)
   v = ctypes.create_string_buffer(pysodium.crypto_core_ristretto255_BYTES)
   kmslib.tuokms_blind(w, r, c, d, a, v)
   return r.raw, c.raw, d.raw, a.raw, v.raw

def thresholdmult(threshold, parts):
   beta = ctypes.create_string_buffer(pysodium.crypto_core_ristretto255_BYTES)
   if kmslib.toprf_thresholdmult(threshold, b''.join(parts[:threshold]), beta) != 0:
       raise ValueError
   return beta.raw

def tuokms_decrypt(ct, r, c, d, pubkey, beta, verifier_beta):
   pt_len = len(ct) - pysodium.crypto_secretbox_NONCEBYTES- pysodium.crypto_secretbox_MACBYTES
   pt = ctypes.create_string_buffer(pt_len)
   if(kmslib.tuokms_decrypt(ct, len(ct), r, c, d, pubkey, beta, verifier_beta, pt)): raise ValueError
   return pt.raw

def decrypt(w,ct,pubkey,servers,threshold,keyid):
   # first blind w
   r,c,d,a,v = blind(w)
   # send to servers
   n = len(servers)
   conns = connect(servers)

   for index,conn in enumerate(conns):
       msg = b"%c%c%c%c%c%s" % (VERSION, Evaluate, index+1, threshold, n, keyid)
       msg += a + v
       msg = struct.pack("H", len(msg)) + msg
       conn.sendall(msg)

   # receive responses from tuokms_evaluate
   responders=gather(conns, 33*2, n, lambda pkt: (pkt[:33], pkt[33:]))

   xresps = tuple(responders[i][0] for i in range(n))
   vresps = tuple(responders[i][1] for i in range(n))

   # we only select the first t shares, should be rather random
   beta = thresholdmult(threshold, xresps)
   beta_verifier = thresholdmult(threshold, vresps)

   return tuokms_decrypt(ct, r, c, d, pubkey, beta, beta_verifier)

def reconstruct(threshold, shares):
   v = ctypes.create_string_buffer(pysodium.crypto_core_ristretto255_SCALARBYTES)
   kmslib.dkg_reconstruct(threshold, b''.join(shares), v)
   return v.raw

def update(servers,threshold,keyid):
   n = len(servers)
   conns = connect(servers)

   for index,c in enumerate(conns):
      msg = b"%c%c%c%c%c%s" % (VERSION, TUOKMS_Update, index+1, threshold, n, keyid)
      msg = struct.pack("H", len(msg)) + msg
      c.sendall(msg)

   expectedmsglen=(pysodium.crypto_core_ristretto255_BYTES * threshold) + (33*n*2)
   responders=gather(conns, expectedmsglen, n, lambda pkt: (pkt[:threshold*pysodium.crypto_core_ristretto255_BYTES], split_by_n(pkt[threshold*pysodium.crypto_core_ristretto255_BYTES:], 2*33)) )
   commitments = b''.join(responders[i][0] for i in range(n))
   for i in range(n):
       shares = b''.join([responders[j][1][i] for j in range(n)])
       msg = commitments + shares
       conns[i].sendall(msg)

   p_shares=gather(conns, 66, n)

   mul_shares=gather(conns, n*33, n, lambda pkt: split_by_n(pkt,33))

   for i in range(n):
       msg = b''.join([mul_shares[j][i] for j in range(n)])
       conns[i].sendall(msg)


   new_shares=gather(conns, 33, n)

   p=reconstruct(threshold, [v for k,v in sorted(p_shares.items())])

   delta = pysodium.crypto_core_ristretto255_scalar_invert(p);

   yc = ctypes.create_string_buffer(pysodium.crypto_core_ristretto255_BYTES)
   shares = b''.join(new_shares[i] for i in range(n))
   kmslib.tuokms_pubkey(n, threshold, shares, yc)

   return yc.raw, delta

def update_w(delta, w):
   kmslib.uokms_update_w(delta,w)
   return w

def test():
   threshold, servers = 3, [("localhost", 10000),
                            ('localhost', 10001),
                            ('localhost', 10002),
                            ('localhost', 10003),
                            ('localhost', 10004)]
   pubkey, keyid = dkg(servers, threshold)
   print("pubkey", pubkey)

   # encrypt something
   w, ct = encrypt(b"hello world", pubkey)
   print(w, ct)

   # decrypt
   print(decrypt(w,ct,pubkey,servers,threshold,keyid))

   pubkey, delta = update(servers, threshold, keyid)
   w = update_w(delta, w)

   print(w, ct)
   print(decrypt(w,ct,pubkey,servers,threshold,keyid))

   w1, ct1 = encrypt(b"foobarbaz23", pubkey)
   print(decrypt(w1,ct1,pubkey,servers,threshold,keyid))

def savekey(keyid, pubkey, threshold):
   # todo make location of pubkeys configurable
   with open(f"keys/{keyid.hex()}", 'wb') as fd:
      fd.write(bytes([threshold]))
      fd.write(pubkey)

def loadkey(keyid):
   with open(f"keys/{keyid}", 'rb') as fd:
      threshold = int(fd.read(1)[0])
      return fd.read(), threshold

def parse_servers(servers, config):
   res = []
   for s in servers or []:
      host, port = s.split(":")
      port = int(port)
      host = host or "localhost"
      res.append((host, port))
   if res: return res

   for k,v in config.get('servers',{}).items():
       host = v.get('host',"localhost")
       port = v.get('port')
       res.append((host, port))
   return res

def getcfg():
  paths=[
      # read global cfg
      '/etc/tuokms/config',
      # update with per-user configs
      os.path.expanduser("~/.tuokmsrc"),
      # over-ride with local directory config
      os.path.expanduser("~/.config/tuokms/config"),
      os.path.expanduser("tuokms.cfg")
  ]
  config = dict()
  for path in paths:
    try:
        with open(path, "rb") as f:
            data = tomllib.load(f)
    except FileNotFoundError:
        continue
    config.update(data)
  return config

def main(params=sys.argv):
    config = getcfg()

    parser = argparse.ArgumentParser(description='tuokms cli'
    f"usage: {sys.argv[0]} -c <genkey|encrypt|decrypt|update>"
    f"       {sys.argv[0]} -c genkey -t threshold -s server1:port server2:port ..."
    f"       {sys.argv[0]} -c encrypt -k keyid <filetoencrypt >encryptedfile"
    f"       {sys.argv[0]} -c decrypt -s server1:port ... serverN:port <filetodecrypt >decryptedfile"
    f"       {sys.argv[0]} -c update -k keyid -s server1:port ... serverN:port <listoffilestoupdate")

    parser.add_argument('-c', '--cmd', choices={"genkey", "encrypt", "decrypt", "update"})
    parser.add_argument('-s', '--server', nargs="+")
    parser.add_argument('-t', '--threshold', type=int)
    parser.add_argument('-k', '--keyid')
    args = parser.parse_args()

    servers=parse_servers(args.server, config)

    if args.cmd=="genkey":
        if args.threshold*2 + 1 < len(servers):
            print("Warning this key will not be updatable.", file=sys.stderr)
            print("You need to have at least 2*threshold+1 servers for updatable keys", file=sys.stderr)
            if input("press y/Y to continue") not in ('y','Y'): return
        pubkey, keyid = dkg(servers, args.threshold)
        savekey(keyid, pubkey, args.threshold)
        print("keyid", keyid.hex())

    elif args.cmd=="encrypt":
        pubkey, _ = loadkey(args.keyid)
        w, ct = encrypt(b"hello world", pubkey)
        sys.stdout.buffer.write(unhexlify(args.keyid))
        sys.stdout.buffer.write(w)
        sys.stdout.buffer.write(ct)

    elif args.cmd=="decrypt":
        keyid = sys.stdin.buffer.read(KEYID_SIZE)
        w = sys.stdin.buffer.read(pysodium.crypto_core_ristretto255_BYTES)
        ct = sys.stdin.buffer.read()
        pubkey, threshold = loadkey(keyid.hex())
        sys.stdout.buffer.write(decrypt(w, ct, pubkey, servers, threshold, keyid))

    elif args.cmd=="update":
        _, threshold = loadkey(args.keyid)
        pubkey, delta = update(servers, threshold, unhexlify(args.keyid))
        savekey(unhexlify(args.keyid), pubkey, threshold)
        for path in sys.stdin:
            with open(path,'r+b') as fd:
                fkeyid = fd.read(KEYID_SIZE)
                if args.keyid!=fkeyid.hex():
                    print(f"{path} is not encrypted using keyid: {args.keyid}, skipping")
                    continue
                w = fd.read(pysodium.crypto_core_ristretto255_BYTES)
                w = update_w(delta, w)
                fd.seek(-pysodium.crypto_core_ristretto255_BYTES,io.SEEK_CUR)
                fd.write(w)
    else:
        parser.print_help()
        usage()

if __name__ == '__main__':
  #test()
  try:
    main(sys.argv)
  except Exception:
    print("fail", file=sys.stderr)
    raise # only for dbg

