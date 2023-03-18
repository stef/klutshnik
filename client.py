#!/usr/bin/env python
# SPDX-FileCopyrightText: 2023, Marsiske Stefan
# SPDX-License-Identifier: GPL-3.0-or-later


import os, io, sys, socket, struct, select
import ctypes, ctypes.util, tomllib
import pysodium, argparse, subprocess
from binascii import unhexlify, a2b_base64, b2a_base64
from dissononce.dh.x25519.keypair import KeyPair
from dissononce.dh.x25519.public import PublicKey
from noiseclient import NoiseWrapper
from opaquestore import opaquestore

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

config = None

def split_by_n(obj, n):
  # src https://stackoverflow.com/questions/9475241/split-string-every-nth-character
  return [obj[i:i+n] for i in range(0, len(obj), n)]

def getpwd(title):
    proc=subprocess.Popen(['/usr/bin/pinentry', '-g'], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err = proc.communicate(input=('SETTITLE vtuokms password prompt\nSETDESC %s\nSETPROMPT opaque-store password\ngetpin\n' % (title)).encode())
    if proc.returncode == 0:
        for line in out.split(b'\n'):
            if line.startswith(b"D "): return line[2:]

def getauthkey(op, keyid):
   cfg = config['opaque-storage']
   if op == DKG:
      keyid = b'unbound'
   keyid=pysodium.crypto_generichash(cfg['username'].encode('utf8') + keyid)
   pwd = getpwd("getting auth token from opaque-store password")
   s = NoiseWrapper.connect(cfg['address'], cfg['port'], cfg['noise_key'], cfg['server_pubkey'])
   return opaquestore.get(s, pwd, keyid)

def setauthkey(keyid, token):
   cfg = config['opaque-storage']
   keyid=pysodium.crypto_generichash(cfg['username'].encode('utf8') + keyid)
   pwd = getpwd("saving auth token to opaque-store password")
   opaquestore.test_pwd(pwd)
   s = NoiseWrapper.connect(cfg['address'], cfg['port'], cfg['noise_key'], cfg['server_pubkey'])
   opaquestore.create(s, pwd, keyid, token)

def connect(servers, op, threshold, n, keyid):
   global config
   if 'authkey' in config:
       authkey = config['authkey']
   else:
       authkey = getauthkey(op, keyid)

   conns = []
   for host,port,pubkey in servers:
       fd = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
       fd.settimeout(15)
       fd.connect((host, port))
       noised =NoiseWrapper(fd, config['key'], pubkey)
       conns.append(noised)

   for index,c in enumerate(conns):
      msg = b"%c%c%c%c%c%s" % (VERSION, op, index+1, threshold, n, keyid)
      c.sendall(msg)

   for c in conns:
      msg = authkey
      c.sendall(msg)

   return conns

def gather(conns, expectedmsglen, n, proc=None):
   responses={}
   while len(responses)!=n:
      fds={x.fd: (i, x) for i,x in enumerate(conns)}
      r, _,_ =select.select(fds.keys(),[],[],5)
      if not r: sys.exit(1)
      for fd in r:
         idx = fds[fd][0]
         if idx in responses:
            continue
         pkt = fds[fd][1].read_pkt(expectedmsglen)
         responses[idx]=pkt if not proc else proc(pkt)
   return responses

def dkg(servers,threshold):
   n = len(servers)
   keyid = pysodium.randombytes(KEYID_SIZE)
   conns = connect(servers, DKG, threshold, n, keyid)

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

   authtoken = conns[0].read_pkt(0)
   setauthkey(keyid,authtoken)
   print("authtoken for new key: ", b2a_base64(authtoken).decode('utf8').strip())

   return yc.raw, keyid

def encrypt(plaintext, yc):
   w = ctypes.create_string_buffer(pysodium.crypto_core_ristretto255_BYTES)
   ciphertext=ctypes.create_string_buffer(len(plaintext)+pysodium.crypto_secretbox_NONCEBYTES+pysodium.crypto_secretbox_MACBYTES)
   kmslib.uokms_encrypt(yc, plaintext, len(plaintext), w, ciphertext)
   return w.raw, ciphertext.raw

def stream_encrypt(yc):
   kmslib.uokms_stream_encrypt(yc, 0, 1)

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

def tuokms_stream_decrypt(w, r, c, d, pubkey, beta, verifier_beta):
   if(kmslib.tuokms_stream_decrypt(0, 1, w, r, c, d, pubkey, beta, verifier_beta)): raise ValueError

def decrypt(w,pubkey,servers,threshold,keyid):
   # first blind w
   r,c,d,a,v = blind(w)
   # send to servers
   n = len(servers)
   conns = connect(servers, Evaluate, threshold, n, keyid)

   for index,conn in enumerate(conns):
       msg = a + v
       conn.sendall(msg)

   # receive responses from tuokms_evaluate
   responders=gather(conns, 33*2, n, lambda pkt: (pkt[:33], pkt[33:]))

   xresps = tuple(responders[i][0] for i in range(n))
   vresps = tuple(responders[i][1] for i in range(n))

   # we only select the first t shares, should be rather random
   beta = thresholdmult(threshold, xresps)
   beta_verifier = thresholdmult(threshold, vresps)

   return tuokms_stream_decrypt(w, r, c, d, pubkey, beta, beta_verifier)

def reconstruct(threshold, shares):
   v = ctypes.create_string_buffer(pysodium.crypto_core_ristretto255_SCALARBYTES)
   kmslib.dkg_reconstruct(threshold, b''.join(shares), v)
   return v.raw

def update(servers,threshold,keyid):
   n = len(servers)
   conns = connect(servers, TUOKMS_Update, threshold, n, keyid)

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
   with open(f"{config['keystore']}/{keyid.hex()}", 'wb') as fd:
      fd.write(bytes([threshold]))
      fd.write(pubkey)

def loadkey(keyid):
   with open(f"keys/{keyid}", 'rb') as fd:
      threshold = int(fd.read(1)[0])
      return fd.read(), threshold

def parse_servers(config):
   res = []
   for k,v in config.get('servers',{}).items():
       host = v.get('host',"localhost")
       port = v.get('port')
       pubkey=PublicKey(a2b_base64(v['pubkey']))
       res.append((host, port, pubkey))
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

  if 'opaque-storage' not in config:
      if 'authkey' not in config:
          raise ValueError("no opaque-storage and no authkey in config file")
      config['authkey']=a2b_base64(config['authkey']+'==')
      return config

  config['opaque-storage']['noise_key']=KeyPair.from_bytes(a2b_base64(config['opaque-storage']['noise_key']+'=='))
  config['opaque-storage']['server_pubkey']=PublicKey(a2b_base64(config['opaque-storage']['server_pubkey']+'=='))
  opaquestore.config = config['opaque-storage']
  return config

def main(params=sys.argv):
    global config
    config = getcfg()

    with open(config['key'],'rb') as fd:
        config['key']=KeyPair.from_bytes(a2b_base64(fd.read()))

    parser = argparse.ArgumentParser(description='tuokms cli'
    f"usage: {sys.argv[0]} -c <genkey|encrypt|decrypt|update>"
    f"       {sys.argv[0]} -c genkey -t threshold ..."
    f"       {sys.argv[0]} -c encrypt -k keyid <filetoencrypt >encryptedfile"
    f"       {sys.argv[0]} -c decrypt <filetodecrypt >decryptedfile"
    f"       {sys.argv[0]} -c update -k keyid <listoffilestoupdate")

    parser.add_argument('-c', '--cmd', choices={"genkey", "encrypt", "decrypt", "update", 'authkey'})
    parser.add_argument('-t', '--threshold', type=int)
    parser.add_argument('-k', '--keyid')
    args = parser.parse_args()

    servers=parse_servers(config)

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
        os.write(1, unhexlify(args.keyid))
        stream_encrypt(pubkey)

    elif args.cmd=="decrypt":
        keyid = os.read(0, KEYID_SIZE)
        w = os.read(0, pysodium.crypto_core_ristretto255_BYTES)
        pubkey, threshold = loadkey(keyid.hex())
        decrypt(w, pubkey, servers, threshold, keyid)

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
    elif args.cmd=="authkey":
        token = a2b_base64(sys.stdin.buffer.readline().rstrip(b'\n')+b'==')
        setauthkey(b'unbound', token)

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

