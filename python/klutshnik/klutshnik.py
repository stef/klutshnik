#!/usr/bin/env python3

# SPDX-FileCopyrightText: 2018-2021, Marsiske Stefan
# SPDX-License-Identifier: GPL-3.0-or-later

import sys, os, struct, json, io, lzma, tempfile, tomlkit, shutil, time
from tempfile import NamedTemporaryFile
import pysodium, pyoprf
from klutshnik.cfg import getcfg
from SecureString import clearmem
from pyoprf.multiplexer import Multiplexer
from binascii import a2b_base64, b2a_base64, unhexlify
from itertools import zip_longest

import ctypes, ctypes.util
klutshniklib = ctypes.cdll.LoadLibrary(ctypes.util.find_library('klutshnik') or
                                 ctypes.util.find_library('libklutshnik.so') or
                                 ctypes.util.find_library('libklutshnik') or
                                 ctypes.util.find_library('libklutshnik0'))
if not klutshniklib._name:
   raise ValueError('Unable to find libklutshnik')

KEYID_SIZE = pysodium.crypto_generichash_BYTES
VERSION = b'\x00'

#### consts ####

CREATE  =b'\x00'
ROTATE  =b'\x33'
REFRESH =b'\x55'
DECRYPT =b'\x66'
DELETE  =b'\xff'
MODAUTH =b'\xaa'


perms = {
'OWNER'  : 1,
'DECRYPT': 2,
'UPDATE' : 4,
'DELETE' : 8,
}

perm_str = { 0: 'none', 1: 'owner', 2: 'decrypt', 3: 'owner,decrypt', 4: 'update', 5: 'owner,update', 6: 'decrypt,update',
             7: 'owner,decrypt,update', 8: 'delete', 9: 'owner,delete', 10: 'decrypt,delete', 11: 'owner,decrypt,delete',
             12: 'update,delete', 13: 'owner,update,delete', 14: 'decrypt,update,delete', 15: 'owner,decrypt,update,delete'}

config = None

#### Helper fns ####

def processcfg(config):
  servers = config.get('servers',{})
  config = config.get('client',{})

  config['threshold'] = int(config.get('threshold') or "1")
  config['ts_epsilon'] = int(config.get('ts_epsilon') or "1200")
  global debug
  debug = config.get('debug', False)

  for server in servers.values():
    if 'ssl_cert' not in server: continue
    server['ssl_cert'] = os.path.expanduser(server['ssl_cert']) # only for dev, production system should use proper certs!

  if len(servers)>1:
      if config['threshold'] < 2:
          print('if you have multiple servers in your config, you must specify a threshold, which must be: len(servers) > threshold > 1 also')
          exit(1)
      if len(servers)<config['threshold']:
          print(f'threshold({config["threshold"]}) must be less than the number of servers({len(servers)}) in your config')
          exit(1)
  elif config['threshold'] > 1:
      print(f'threshold({config["threshold"]}) must be less than the number of servers({len(servers)}) in your config')
      exit(1)
  config['servers']=servers

  return config

def split_by_n(iterable, n):
    return list(zip_longest(*[iter(iterable)]*n, fillvalue=''))

def read_pkt(s,i,plen=None):
   res = []
   if plen is None:
     plen = s[i].read(2)
     if len(plen)!=2:
       raise ValueError
     plen = struct.unpack(">H", plen)[0]

   read = 0
   while read<plen and (len(res)==0 or len(res[-1])!=0):
     res.append(s[i].read(plen-read))
     read+=len(res[-1])

   if len(res[-1])==0 and read<plen:
     if b''.join(res) == b"\x00\x04fail":
       return
     raise ValueError(f"short read only {len(b''.join(res))} instead of expected {plen} bytes")
   return b''.join(res)

def send_pkt(s, msg, i=None):
  plen = struct.pack(">H", len(msg))
  if i is None:
    s.broadcast(plen+msg)
  else:
    s.send(i, plen+msg)

def savemeta(keyid, pubkey, pkis, threshold, epoch, servers=None):
  path = f"{config['keystore']}/{keyid.hex()}"
  if not os.path.exists(path):
     os.mkdir(path,0o700)

  if servers is not None:
     with open(f"{path}/servers", 'w') as fd:
        tomlkit.dump(servers, fd)

  with open(f"{path}/keyid", 'wb') as fd:
    fd.write(keyid)

  with open(f"{path}/data", 'wb') as fd:
    fd.write(bytes([threshold, len(pkis)]))
    fd.write(struct.pack('>I', epoch))
    fd.write(pubkey)
    fd.write(b''.join(pkis))
    fd.flush()

def readall(fd, size):
    data=[]
    remaining= size
    while remaining>0:
        d= fd.read(remaining)
        if len(d)==0:
            raise IOError("Failed to read enough data")
        data.append(d)
        remaining-= len(d)
    return b''.join(data)

def connect_servers(setup):
   ssl_cert_paths = []
   servers = dict(setup)
   for name, s in setup.items():
      s = dict(s)
      servers[name]=s
      if 'ltsigkey' not in s:
         if 'ltsigkey_path' not in s:
            raise ValueError(f"server '{name}' has no ltsigkey configured")
         with open(s['ltsigkey_path'],'rb') as fd:
            s['ltsigkey'] = fd.read()
      else:
         s['ltsigkey']=a2b_base64(s['ltsigkey'])
      if not 'ssl_cert' in s: continue
      fd, path = tempfile.mkstemp(text=True)
      os.write(fd, s['ssl_cert'].encode('utf8'))
      os.close(fd)
      ssl_cert_paths.append(path)
      s['ssl_cert']=path

   m = Multiplexer(servers)
   m.connect()
   for p in ssl_cert_paths:
      os.remove(p)
   return m

def loadmeta(keyid):
  if not os.path.exists(f"{config['keystore']}/{keyid.hex()}"):
     raise ValueError("unknown keyid")
  try:
    with open(f"{config['keystore']}/{keyid.hex()}/keyid", 'rb') as fd:
       keyid = fd.read(KEYID_SIZE)
    with open(f"{config['keystore']}/{keyid.hex()}/data", 'rb') as fd:
      threshold = int(fd.read(1)[0])
      n = int(fd.read(1)[0])
      epoch = struct.unpack('>I', fd.read(4))[0]
      # load also owners ltsig pk
      pki = fd.read(pysodium.crypto_core_ristretto255_BYTES)
      pkis = readall(fd, (pysodium.crypto_core_ristretto255_BYTES+1) * n)
    with open(f"{config['keystore']}/{keyid.hex()}/servers", 'rb') as fd:
       servers = tomlkit.load(fd)
    servers=dict(servers)
    for s in servers.keys():
       servers[s]=dict(servers[s])
       if 'bleaddr' in servers[s] or 'usb_serial' in servers[s]:
          servers[s]['client_sk']=a2b_base64(servers[s]['client_sk'])
          servers[s]['device_pk']=a2b_base64(servers[s]['device_pk'])
    m = connect_servers(servers)
  except FileNotFoundError:
    raise ValueError("unknown keyid")

  return m, keyid, pki, epoch, threshold, pkis

def getltsigkey():
   if 'ltsigkey' not in config:
      if 'ltsigkey_path' in config:
        with open(config['ltsigkey_path'],'rb') as fd:
          sk = fd.read()
      else:
         if config.get('verbose') == True:
            print("reading lt sigkey from stdin", file=sys.stderr)
         prefix = os.read(0, 6)
         if not prefix == b"kltsk-": raise ValueError(f"invalid long-term sig key on stdin: {repr(prefix)}")
         sk = a2b_base64(os.read(0, 88))
      if len(sk)!=64: raise ValueError("invalid long-term sig key on stdin")
   else:
      sk = a2b_base64(os.read(0, 88))
   return sk

def get_servers(keyid = None):
   servers = {}
   for name, s in config['servers'].items():
      if 'bleaddr' in s:
         x={'bleaddr': s['bleaddr'],
            'client_sk': s['client_sk'],
            'device_pk': s['device_pk']}
      elif 'usb_serial' in s:
         x={'usb_serial': s['usb_serial'],
            'client_sk': s['client_sk'],
            'device_pk': s['device_pk']}
      else:
         x = {'host': s['host'],
              'port': s['port']}
      if 'ltsigkey' in s:
         x['ltsigkey']=s['ltsigkey']
      else:
         with open(s['ltsigkey_path'],'rb') as fd:
            x['ltsigkey']=b2a_base64(fd.read(32)).decode('utf8').strip()
      if 'ssl_cert' in s:
         with open(s['ssl_cert'],'r') as fd:
            x['ssl_cert']=fd.read()
      servers[name]=x
   return servers

#### OPs ####

def init():
   if not os.path.exists(config['keystore']):
      os.makedirs(config['keystore'], mode=0o700)
      print(f"Created missing directory for keystore at '{config['keystore']}'.", file=sys.stderr)

   if 'ltsigkey_path' not in config:
      print(f"The `ltsigkey` configuration value is not set\n."
            f"Please uncomment the line and use the default or some prefered path to store this private key.\n"
            f"aborting.",
            file=sys.stderr)
      return False
   if os.path.exists(config['ltsigkey_path']):
      print(f"{config['ltsigkey_path']} exists, refusing to overwrite.\n"
            f"if you want to generate a new one, delete the old one first.\n"
            f"aborting",
            file=sys.stderr)
      return False
   pk, sk = pysodium.crypto_sign_keypair()

   with open(config['ltsigkey_path'], 'wb') as fd:
     fd.write(sk)

   print(f"Succsessfully generated long-term signing key pair.\n"
         f"Stored the private key at '{config['ltsigkey_path']}'.\n"
         f"Make sure you keep this key secure and have a backup.\n"
         f"Your public key is:\n",
         end="\n\t",
         file=sys.stderr)
   # todo since we use tomlkit we can actually write this value back.
   print(f"LTSIGPK-{b2a_base64(pk).decode('utf8').strip()}", flush=True)
   print(f"\nplease add it to your configuration 'ltsigpub' variable\n"
         f"and ask the admins of the KMS servers you have configured\n"
         f"to add this to their authorized_keys file",
         file=sys.stderr)
   return True

def create(m, keyid, ltsigpub, ltsigkey, t, ts_epsilon, sig_pks):
  op = CREATE
  n = len(m)

  stp, msg0 = pyoprf.stp_dkg_start_stp(n, t, ts_epsilon, "klutshnik v1.0 stp dkg", sig_pks, ltsigkey)
  m.broadcast(op+VERSION+keyid+msg0)

  while pyoprf.stp_dkg_stp_not_done(stp):
    cur_step = pyoprf.stp_dkg_stpstate_step(stp)
    ret, sizes = pyoprf.stp_dkg_stp_input_sizes(stp)
    #print(f"step: {cur_step} {ret} {sizes}", file=sys.stderr)
    peer_msgs = []
    if ret:
      if sizes[0] > 0:
        #print(f"step({cur_step}) gathering sizes", file=sys.stderr)
        peer_msgs_sizes = m.gather(2,n)
        #print(f"step({cur_step}) received {[len(r) for r in peer_msgs_sizes]}", file=sys.stderr)
        for i, (msize, size) in enumerate(zip(peer_msgs_sizes, sizes)):
          if len(msize)!=2:
            raise ValueError(f"peer{i} ({m[i].name}{m[i].address}) sent invalid length indicator (len({msize})) response, should be 2")
          if struct.unpack(">H", msize)[0]!=size:
            raise ValueError(f"peer{i} ({m[i].name}{m[i].address}) sent invalid sized ({msize}) response, should be {size}")
        #print(f"step({cur_step}) gathering {sizes[0]}", file=sys.stderr)
        peer_msgs = m.gather(sizes[0],n)
        #print(f"step({cur_step}) received {[len(r) for r in peer_msgs]}", file=sys.stderr)
    else:
      peer_msgs = [read_pkt(m, i) if s>0 else b'' for i, s in enumerate(sizes)]
    for i, (pkt, size) in enumerate(zip(peer_msgs, sizes)):
      if(len(pkt)!=size):
        raise ValueError(f"peer{i} ({m[i].name}{m[i].address}) sent invalid sized ({len(pkt)}) response, should be {size}")
      #print(f"[{i}] received {pkt.hex()}", file=sys.stderr)
    msgs = b''.join(peer_msgs)

    try:
      out = pyoprf.stp_dkg_stp_next(stp, msgs)
    except Exception as e:
      m.close()
      if pyoprf.stp_dkg_stpstate_cheater_len(stp) > 0:
        cheaters, cheats = pyoprf.stp_dkg_get_cheaters(stp)
        msg=[f"Warning during the distributed key generation the peers misbehaved: {sorted(cheaters)}"]
        for k, v in cheats:
          msg.append(f"\tmisbehaving peer: {k} was caught: {v}")
        msg = '\n'.join(msg)
        raise ValueError(msg)
      else:
        raise ValueError(f"{e} | tp step {cur_step}")
    #print(f"step({cur_step}) outlen: {len(out)}", file=sys.stderr)
    if(len(out)>0):
      for i in range(pyoprf.stp_dkg_stpstate_n(stp)):
        msg = pyoprf.stp_dkg_stp_peer_msg(stp, out, i)
        #print(f"sending({i} {m[i].name}({m[i].address}), {msg.hex()})", file=sys.stderr)
        send_pkt(m, msg, i)

  pkis = tuple(p for p in m.gather(33) if p is not None)
  if len(pkis) != n:
    raise ValueError("only {len(pkis)} out of {n} peers responded with their pubkey shares")
  pki = pyoprf.thresholdmult(pkis[:t])

  auth0 = sig_pks[0] + b'\x4f'
  sig = pysodium.crypto_sign_detached(auth0, ltsigkey)
  send_pkt(m, sig+auth0)

  return keyid, b'\x00\x00\x00\x00', pki, pkis

def rotate(m, keyid, ltsigpub, ltsigkey, t, ts_epsilon, sig_pks, lepoch):
  n = len(m)
  stp, msg0 = pyoprf.tupdate_start_stp(n, t, ts_epsilon, "klutshnik update", sig_pks, keyid, ltsigkey)
  m.broadcast(ROTATE+VERSION+keyid+msg0+ltsigpub)

  auth(m, ROTATE, keyid, msg0+sig_pks[0], ltsigkey)

  while pyoprf.tupdate_stp_not_done(stp):
    cur_step = pyoprf.tupdate_stpstate_step(stp)
    ret, sizes = pyoprf.tupdate_stp_input_sizes(stp)
    peer_msgs = []
    # peer_msgs = (recv(size) for size in sizes)
    if ret:
      if sizes[0] > 0:
        peer_msgs_sizes = m.gather(2,n) #,debug=True)
        for i, (msize, size) in enumerate(zip(peer_msgs_sizes, sizes)):
          if struct.unpack(">H", msize)[0]!=size:
            raise ValueError(f"peer{i} ({m[i].name}{m[i].address}) sent invalid sized ({msize}) response, should be {size}")
        peer_msgs = m.gather(sizes[0],n) #,debug=True)
    else:
      peer_msgs = [read_pkt(m, i) if s>0 else b'' for i, s in enumerate(sizes)]
    for i, (pkt, size) in enumerate(zip(peer_msgs, sizes)):
      if(len(pkt)!=size):
        raise ValueError(f"peer{i} ({m[i].name}{m[i].address}) sent invalid sized ({len(pkt)}) response, should be {size}")
      #print(f"[{i}] received {pkt.hex()}", file=sys.stderr)
    msgs = b''.join(peer_msgs)

    try:
      out = pyoprf.tupdate_stp_next(stp, msgs)
    except Exception as e:
      m.close()
      #if pyoprf.toprf_update_stpstate_cheater_len(stp) > 0:
      #  cheaters, cheats = pyoprf.stp_dkg_get_cheaters(stp)
      #  msg=[f"Warning during the tOPRF key update the peers misbehaved: {sorted(cheaters)}"]
      #  for k, v in cheats:
      #    msg.append(f"\tmisbehaving peer: {k} was caught: {v}")
      #  msg = '\n'.join(msg)
      #  raise ValueError(msg)
      #else:
      #  raise ValueError(f"{e} | tp step {cur_step}")
      raise ValueError(f"{e} | tp step {cur_step}")

    #print(f"outlen: {len(out)}", file=sys.stderr)
    if(len(out)>0):
      for i in range(pyoprf.tupdate_stpstate_n(stp)):
        msg = pyoprf.tupdate_stp_peer_msg(stp, out, i)
        #print(f"sending({i} {m[i].name}({m[i].address}), {msg.hex()})", file=sys.stderr)
        send_pkt(m, msg, i)

  delta = pyoprf.tupdate_stpstate_delta(stp)

  resps = tuple(p for p in m.gather(4+33, proc=lambda x: (x[:4], x[4:])) if p is not None)
  if len(resps) != n:
    raise ValueError("only {len(resps)} out of {n} peers responded with their pubkey shares")
  pkis = [x[1] for x in resps]
  pki = pyoprf.thresholdmult(pkis[:t])

  epoch = set(struct.unpack(">I", r[0])[0] for r in resps)
  if len(epoch) != 1: raise ValueError(f"inconsistent epochs received: {epoch}")
  epoch = tuple(epoch)[0]
  if epoch <= lepoch: raise ValueError(f"locally cached epoch({lepoch}) is greater or equal to rotated epoch({epoch})")

  return keyid, t, epoch, pki, pkis, delta

def encrypt(keyid, yc):
   os.write(1, keyid)
   klutshniklib.klutshnik_stream_encrypt(yc, 0, 1)
   return True

def decrypt(m, keyid, ltsigpub, ltsigkey, t, epoch, pubkey, pkis):
  fepoch = struct.unpack(">I", os.read(0, 4))[0]
  if fepoch!=epoch:
     if (fepoch > epoch):
        raise ValueError(f"data is encrypted with a key from the future: {fepoch}, while we have {epoch}, try again after refreshing the local keymaterial.")
     raise ValueError(f"data is encrypted with a key from {fepoch}, while we have {epoch}. Someone forgot to update the encryption on this data.")

  w = os.read(0, pysodium.crypto_core_ristretto255_BYTES)
  if not pysodium.crypto_core_ristretto255_is_valid_point(w):
     raise ValueError("w value is invalid")

  r = pysodium.crypto_core_ristretto255_scalar_random()
  a = pysodium.crypto_scalarmult_ristretto255(r, w)

  c = pysodium.crypto_core_ristretto255_scalar_random()
  v = pysodium.crypto_scalarmult_ristretto255(c, w)
  d = pysodium.crypto_core_ristretto255_scalar_random()
  tmp = pysodium.crypto_scalarmult_ristretto255_base(d)
  v = pysodium.crypto_core_ristretto255_add(v, tmp)

  # send to servers
  msg = a + v

  m.broadcast(DECRYPT+VERSION+keyid+msg+ltsigpub)

  auth(m, DECRYPT, keyid, msg+ltsigpub, ltsigkey)

  # receive responses from tuokms_evaluate
  resps = tuple((pkt[:33], pkt[33:]) for pkt in m.gather(33*2) if pkt is not None)
  if len(resps) < t:
    raise ValueError("not enough responses received for decrypting")
  xresps = tuple(v[0] for v in resps)
  vresps = tuple(v[1] for v in resps)

  beta = pyoprf.thresholdmult(xresps[:t])
  v_beta = pyoprf.thresholdmult(vresps[:t])

  dek = ctypes.create_string_buffer(pysodium.crypto_secretbox_KEYBYTES)
  ret = klutshniklib.klutshnik_decrypt_get_dek(r,c,d,pubkey,beta,v_beta, dek)
  if(0!=ret):
    if ret==1: raise ValueError("invalid values provided while recovering DEK")
    pkis = split_by_n(pkis, pysodium.crypto_core_ristretto255_BYTES+1)
    cheaters = set()
    for i, (pki, bi, vi) in enumerate(zip(pkis, xresps, vresps)):
      pki = bytes(pki)
      gk = ctypes.create_string_buffer(pysodium.crypto_core_ristretto255_BYTES)
      ret = klutshniklib.klutshnik_verify_zk_proof(r,c,d,pki[1:],bi[1:],vi[1:], gk)
      if(ret==2):
        cheaters.add(i+1)
    for cheater in sorted(cheaters):
      print(f"cheater identified: server {m[cheater-i].name} was caught sending an invalid response to our decryption query",file=sys.stderr)
    ids = sorted({b[0] for b in xresps} - cheaters)
    if len(ids)>t:
      print(f"trying to recover from cheater(s)",file=sys.stderr)
      x = tuple(resps[i-1][0] for i in ids)
      v = tuple(resps[i-1][1] for i in ids)
      beta = pyoprf.thresholdmult(x[:t])
      v_beta = pyoprf.thresholdmult(v[:t])
      ret = klutshniklib.klutshnik_decrypt_get_dek(r,c,d,pubkey,beta,v_beta, dek)
      if ret!=0:
        raise ValueError("failed to recover from cheating")

  if(0!=klutshniklib.stream_decrypt(0,1,dek)): raise ValueError("message forged")
  return True

def update(keyid, delta, epoch):
  for path in sys.stdin:
    path = path.strip()
    with open(path,'r+b') as fd:
        fkeyid = fd.read(KEYID_SIZE)
        if keyid!=fkeyid:
            if config.get('verbose'): print(f"{path} is not encrypted using keyid: {args.keyid}, skipping")
            continue
        fepoch = struct.unpack(">I", fd.read(4))[0]
        if fepoch+1 != epoch:
           print("epoch of file {path} should be {epoch-1} is instead {fepoch}. skipping", file=sys.stderr)
           continue
        w = fd.read(pysodium.crypto_core_ristretto255_BYTES)
        w = pysodium.crypto_scalarmult_ristretto255(delta, w)
        fd.seek(-pysodium.crypto_core_ristretto255_BYTES,io.SEEK_CUR)
        fd.seek(-4,io.SEEK_CUR)
        fd.write(struct.pack(">I", epoch))
        fd.write(w)
  return True

def refresh(m, keyid, ltsigpub, ltsigkey, t, lepoch, lpki, lpkis):
  n = len(m)
  # load peer long-term keys
  m.broadcast(REFRESH+VERSION+keyid+ltsigpub)

  auth(m, REFRESH, keyid, ltsigpub, ltsigkey)

  resps = tuple(p for p in m.gather(4+33, proc=lambda x: (x[:4], x[4:])) if p is not None)
  if len(resps) != n:
    raise ValueError("only {len(resps)} out of {n} peers responded with their pubkey shares")
  pkis = [x[1] for x in resps]
  pki = pyoprf.thresholdmult(pkis[:t])

  save = False
  epoch = set(struct.unpack(">I", r[0])[0] for r in resps)
  if len(epoch) != 1: raise ValueError(f"inconsistent epochs received: {tmp}")
  epoch = tuple(epoch)[0]
  if epoch < lepoch: raise ValueError(f"locally cached epoch({lepoch}) is greater or equal to rotated epoch({epoch})")
  if epoch == lepoch:
     if pki != lpki: raise ValueError(f"epoch matches between KMS and local data, but public key for the current epoch does not")
     if b''.join(pkis) != lpkis:
        raise ValueError(f"epoch matches between KMS and local data, but public key shares for the current epoch does not")
  else:
     save = True
  return save, keyid, pki, pkis, t, epoch

def delete(m, keyid, ltsigpub, ltsigkey):
  m.broadcast(DELETE+VERSION+keyid+ltsigpub)

  auth(m, DELETE, keyid, ltsigpub, ltsigkey)

  ret = True
  resps = m.gather(2)
  for i, r in enumerate(resps):
    if r != b'ok':
      print(f"failed to delete on {m[i].name}")
      ret = False

  shutil.rmtree(f"{config['keystore']}/{keyid.hex()}")

  return ret

def auth(m, op, keyid, reqbuf, sk):
  sizes = tuple(p for p in m.gather(2) if struct.unpack(">H", p)[0] != 32)
  if sizes != tuple(): raise ValueError("failed to receive auth nonces")

  nonces = tuple(p for p in m.gather(32) if p is not None)
  if len(nonces) != len(m):
    raise ValueError("only {len(nonces)} out of {len(m)} peers responded with auth nonces")

  for i, nonce in enumerate(nonces):
    resp = pysodium.crypto_sign_detached(op+VERSION+keyid+reqbuf+nonce,sk)
    #print(f"sig: {resp.hex()}\ndata: {(op+VERSION+keyid+reqbuf+nonce).hex()}", file=sys.stderr)
    send_pkt(m, resp, i)

def deluser(m, keyid, ltsigpub, ltsigkey, pubkey):
  pubkey = a2b_base64(pubkey)
  opcode = b'\x00'

  m.broadcast(MODAUTH+VERSION+keyid+opcode)

  auth(m, MODAUTH, keyid, opcode, ltsigkey)

  sizes = tuple(struct.unpack(">H", p)[0] for p in m.gather(2) if p is not None)
  if len(sizes) != len(m): raise ValueError("failed to receive auth blob sizes")
  if len(set(sizes)) != 1: raise ValueError("received inconsistent auth blob sizes")
  size = tuple(set(sizes))[0]

  authblobs = tuple(p for p in m.gather(size) if p is not None)
  if len(authblobs) != len(m): raise ValueError("failed to receive auth blob sizes")
  if len(set(authblobs)) != 1: raise ValueError("received inconsistent auth blob sizes")

  authblob = tuple(set(authblobs))[0]

  sig = authblob[:pysodium.crypto_sign_BYTES]
  data = authblob[pysodium.crypto_sign_BYTES:]
  try:
    pysodium.crypto_sign_verify_detached(sig, data, ltsigpub)
  except:
    raise ValueError("invalid signature on authblob")

  items = {bytes(e[:32]): e[32]&0xf for e in split_by_n(data, pysodium.crypto_sign_PUBLICKEYBYTES+1)}
  del items[pubkey]

  auth2 = b''.join(k+bytes([p]) for k,p in items.items())

  sig = pysodium.crypto_sign_detached(auth2,ltsigkey)
  msg = sig+auth2
  for i in range(len(m)):
    send_pkt(m, msg, i)
  return True

def adduser(m, keyid, ltsigpub, ltsigkey, userpub, perm, t, servers):
  pubkey = a2b_base64(userpub)
  m.broadcast(MODAUTH+VERSION+keyid+b'\x00')
  auth(m, MODAUTH, keyid, b'\x00', ltsigkey)

  sizes = tuple(struct.unpack(">H", p)[0] for p in m.gather(2) if p is not None)
  if len(sizes) != len(m): raise ValueError("failed to receive auth blob sizes")
  if len(set(sizes)) != 1: raise ValueError("received inconsistent auth blob sizes")
  size = tuple(set(sizes))[0]

  authblobs = tuple(p for p in m.gather(size) if p is not None)
  if len(authblobs) != len(m): raise ValueError("failed to receive auth blob sizes")
  if len(set(authblobs)) != 1: raise ValueError("received inconsistent auth blob sizes")

  authblob = tuple(set(authblobs))[0]

  pk = a2b_base64(config['ltsigpub'][8:])
  sig = authblob[:pysodium.crypto_sign_BYTES]
  data = authblob[pysodium.crypto_sign_BYTES:]

  try:
    pysodium.crypto_sign_verify_detached(sig, data, pk)
  except:
    raise ValueError("invalid signature on authblob")

  items = {bytes(e[:32]): e[32]&0xf for e in split_by_n(data, pysodium.crypto_sign_PUBLICKEYBYTES+1)}
  if config.get('verbose') == True and items.get(pubkey) == perm:
    print(f"{pk.hex()} already has perm ({items.get(pubkey)} == {perm}): {perm_str[perm]}", file=sys.stderr)
  items[pubkey]=perm

  auth2 = b''.join(k+bytes([p]) for k,p in items.items())
  sig = pysodium.crypto_sign_detached(auth2,ltsigkey)
  msg = sig+auth2
  for i in range(len(m)):
    send_pkt(m, msg, i)

  # serialize:
  # keyid, t, config['servers']
  return json.dumps({'n': len(m), 't': t, 'keyid': b2a_base64(keyid).decode('utf8').strip(), 'servers': servers})

def listusers(m, keyid, ltsigpub, ltsigkey):
  opcode = b'\x01'
  m.broadcast(MODAUTH+VERSION+keyid+opcode)

  auth(m, MODAUTH, keyid, opcode, ltsigkey)

  sizes = tuple(struct.unpack(">H", p)[0] for p in m.gather(2) if p is not None)
  if len(sizes) != len(m): raise ValueError("failed to receive auth blob sizes")
  if len(set(sizes)) != 1: raise ValueError("received inconsistent auth blob sizes")
  size = tuple(set(sizes))[0]

  authblobs = tuple(p for p in m.gather(size) if p is not None)
  if len(authblobs) != len(m): raise ValueError("failed to receive auth blob sizes")
  if len(set(authblobs)) != 1: raise ValueError("received inconsistent auth blob sizes")

  authblob = tuple(set(authblobs))[0]

  pk = a2b_base64(config['ltsigpub'][8:])
  sig = authblob[:pysodium.crypto_sign_BYTES]
  data = authblob[pysodium.crypto_sign_BYTES:]

  try:
    pysodium.crypto_sign_verify_detached(sig, data, pk)
  except:
    raise ValueError("invalid signature on authblob")

  items = {bytes(e[:32]): e[32]&0xf for e in split_by_n(data, pysodium.crypto_sign_PUBLICKEYBYTES+1)}
  for pk, p in items.items():
      print(pk.hex(), perm_str[p])
  return True

def import_cfg(keyid, ltsigpub, ltsigkey, export):
   # todo also support importing KLTPK- pubkeys for encryption only, or urls pointing at them
   if not export.startswith("KLTCFG-"): raise ValueError("data to be imported does not have expected prefix")
   data = json.loads(lzma.decompress(a2b_base64(export[7:])))
   if data['n']!=len(data['servers']): raise ValueError("specified n parameter inconsistent with number of specified servers")
   n = data['n']
   t = data['t']
   if t > 2 or t >= n or (t-1)*2+1>n: raise ValueError("invalid threshold value")
   owner_keyid = a2b_base64(data['keyid'])

   servers = {name: {k:v for k, v in s.items()} for name,s in data['servers'].items()}
   for s in data['servers'].values():
      if "bleaddr" in s or 'usb_serial' in s:
         s['client_sk']=a2b_base64(s['client_sk'])
         s['device_pk']=a2b_base64(s['device_pk'])

   m = connect_servers(data['servers'])
   # load peer long-term keys
   m.broadcast(REFRESH+VERSION+owner_keyid+ltsigpub)

   auth(m, REFRESH, owner_keyid, ltsigpub, ltsigkey)

   resps = tuple(p for p in m.gather(4+33, proc=lambda x: (x[:4], x[4:])) if p is not None)
   m.close()
   if len(resps) != n:
      raise ValueError("only {len(resps)} out of {n} peers responded with their pubkey shares")
   pkis = [x[1] for x in resps]
   pki = pyoprf.thresholdmult(pkis[:t])
   epoch = set(struct.unpack(">I", r[0])[0] for r in resps)
   if len(epoch) != 1: raise ValueError(f"inconsistent epochs received: {epoch}")
   epoch = tuple(epoch)[0]

   savemeta(owner_keyid, pki, pkis, t, epoch, servers)
   cwd = os.getcwd()
   os.chdir(f"{config['keystore']}")
   os.symlink(f"{owner_keyid.hex()}", f"{keyid.hex()}")
   os.chdir(cwd)

   return True

def provision(port, cfg_file, cfg, authkeys, uart, esp):
   # reset device
   if esp:
      from esptool.cmds import detect_chip
      with detect_chip(port) as esp:
         esp.connect()
         esp.hard_reset()

   import serial
   serialPort = serial.Serial(port=port, baudrate=115200, timeout=0.5)
   for _ in range(100):
      line = serialPort.readline().decode("Ascii").strip()
      if debug: print(line)
      if 'no configuration found. waiting for client initialization' in line:
         print("device is unintialized. sending client config", file=sys.stderr)
         serialPort.reset_input_buffer()
         ltsigpub = cfg['client']['ltsigpub'][8:]
         serialPort.write(f'init ltsig {ltsigpub}\n'.encode('utf8'))
         time.sleep(0.1)
         noise_sk = pysodium.randombytes(32)
         noise_pk = pyoprf.noisexk.pubkey(noise_sk)
         serialPort.write(f'init noise {b2a_base64(noise_pk).decode('utf8').strip()}\n'.encode('utf8'))
         time.sleep(0.1)
         for ak in authkeys:
            if ak.strip() == '': continue
            serialPort.write(f"authkey add {ak}\n".encode('utf8'))
            time.sleep(0.1)
         break
   else:
      raise ValueError("unexpected initialization")

   print("waiting a bit for device to generate its own keys", file=sys.stderr)
   time.sleep(0.4)
   # todo maybe check if any of the init ops gave any negative results
   serialPort.reset_input_buffer()
   # collect info
   serialPort.write(b'getcfg noisepk\n')
   time.sleep(0.1)
   _ = serialPort.readline().decode("Ascii").strip()
   line = serialPort.readline().decode("Ascii").strip()
   npk=a2b_base64(line.split()[-1])

   serialPort.reset_input_buffer()
   serialPort.write(b'getcfg ltsigpk\n')
   time.sleep(0.1)
   _ = serialPort.readline().decode("Ascii").strip()
   line = serialPort.readline().decode("Ascii").strip()
   spk=a2b_base64(line.split()[-1])

   if not uart:
      serialPort.reset_input_buffer()
      serialPort.write(b'getcfg mac\n')
      time.sleep(0.1)
      _ = serialPort.readline().decode("Ascii").strip()
      line = serialPort.readline().decode("Ascii").strip()
      if line == "No MAC, this klutshnik device doesn't do BLE":
         mac=None
      elif line.startswith('MAC address: '):
         mac=line.split()[-2]
      else:
         print(line,file=sys.stderr)
         raise ValueError("failed to retrieve mac address from device")
      name = f"ble_{mac.replace(':','')}"
   else:
      mac=None
      name = f"usb-cdc0"

   table = None
   # check if there is already a record with this mac
   for k, server in cfg.get('servers',{}).items():
      if k == name:
         print(f'warning: there is already a server configured with the name "{name}", will overwrite values in there', file=sys.stderr)
         shutil.copy2(cfg_file, f"{cfg_file}.bak")
         table = server
      elif uart is None and server.get('bleaddr') == mac:
         print(f'warning: this config already has a server configured with the name: "{k}"\n'
               f'you should merge this entry with the new entry called "{name}"', file=sys.stderr)
   if table is None:
      table = tomlkit.table(False)
      cfg.get('servers').append(name, table)

   if mac is not None:
      table.update({'bleaddr': mac})
   elif uart is not None:
      table.update({'usb_serial': uart})

   table.update({'ltsigkey': b2a_base64(spk).decode('utf8').strip(),
                 'device_pk': b2a_base64(npk).decode('utf8').strip(),
                 'client_sk': b2a_base64(noise_sk).decode('utf8').strip(),
                 })

   with NamedTemporaryFile(mode="w+", dir=os.path.dirname(cfg_file), delete=False, delete_on_close=False) as tmpfile:
       tname = tmpfile.name
       tomlkit.dump(cfg, tmpfile)
   os.replace(tname, cfg_file);
   print(f'please add {b2a_base64(spk+npk).decode().strip()} to all other klutshnikd servers authorized_keys files you intend to use in a group')
   return True

def usage(params, help=False):
  name = os.path.basename(params[0])
  print("usage:")
  print("     %s create  <keyid> [<ltsigkey] >pubkey" % name)
  print("     %s encrypt <pubkey> <plaintext >ciphertext" % name)
  print("     %s decrypt [<ltsigkey] <ciphertext >plaintext" % name)
  print("     %s rotate  <keyid> [<ltsigkey] >newpk-and-delta" % name)
  print("     %s refresh <keyid> [<ltsigkey]" % name)
  print("     %s delete  <keyid> [<ltsigkey]" % name)
  print("     %s update  <delta <files2update" % name)
  print("     %s adduser <keyid> <b64 pubkey> <owner,decrypt,update,delete> [<ltsigkey]" % name)
  print("     %s deluser <keyid> <b64 pubkey> [<ltsigkey]" % name)
  print("     %s listusers <keyid> [<ltsigkey]" % name)
  print("     %s import <keyid> <KLTCFG-...> [<ltsigkey]" % name)
  print("     %s provision <serial port> <klutshnik.cfg> <authorized_keys> <uart|esp> [<ltsigkey]" % name)

  if help: sys.exit(0)
  sys.exit(100)

def getargs(config, cmd, params):
   if cmd == create:
      keyid = pysodium.crypto_generichash(params[0], k=config['id_salt'])
      t = config['threshold']
      ts_epsilon=config['ts_epsilon']
      sig_pks = [a2b_base64(config['ltsigpub'][8:])]
      servers={}
      for name, server in config['servers'].items():
         server=dict(server)
         servers[name]=(server)
         if 'bleaddr' in server or 'usb_serial' in server:
            server['client_sk']=a2b_base64(server['client_sk'])
            server['device_pk']=a2b_base64(server['device_pk'])
         if 'ltsigkey' in server:
            sig_pks.append(a2b_base64(server['ltsigkey']))
            continue
         with open(server.get('ltsigkey_path'),'rb') as fd:
           ltpk = fd.read()
           if(len(ltpk)!=pysodium.crypto_sign_PUBLICKEYBYTES):
             raise ValueError(f"long-term signature key for server {name} is of incorrect size")
           sig_pks.append(ltpk)
      ltsigkey = getltsigkey()
      m = Multiplexer(servers)
      m.connect()
      return m, keyid, sig_pks[0], ltsigkey, t, ts_epsilon, sig_pks

   if cmd == rotate:
      keyid = pysodium.crypto_generichash(params[0], k=config['id_salt'])
      ts_epsilon=config['ts_epsilon']
      m, keyid, _, epoch, t, _ = loadmeta(keyid)
      ltsigpub = a2b_base64(config['ltsigpub'][8:])
      sig_pks = [ltsigpub]
      with open(f"{config['keystore']}/{keyid.hex()}/servers", 'rb') as fd:
         servers = tomlkit.load(fd)
      for name, server in servers.items():
         sig_pks.append(a2b_base64(server['ltsigkey']))
         continue
      ltsigkey = getltsigkey()
      return m, keyid, ltsigpub, ltsigkey, t, ts_epsilon, sig_pks, epoch

   if cmd == encrypt:
      if not params[0].startswith("KLCPK-"):
         raise ValueError("invalid pubkey provided")
      raw = a2b_base64(params[0][6:])
      keyid = raw[:KEYID_SIZE+4]
      yc = raw[KEYID_SIZE+4:]
      return keyid, yc

   if cmd == decrypt:
      ltsigkey = getltsigkey()
      keyid = os.read(0, KEYID_SIZE)
      ltsigpub = a2b_base64(config['ltsigpub'][8:])
      m, _, pki, epoch, t, pkis = loadmeta(keyid)
      return m, keyid, ltsigpub, ltsigkey, t, epoch, pki, pkis

   if cmd == adduser:
      keyid = pysodium.crypto_generichash(params[0], k=config['id_salt'])
      ltsigkey = getltsigkey()
      ltsigpub = a2b_base64(config['ltsigpub'][8:])
      m, keyid, _, _, t, _ = loadmeta(keyid)
      perm = 0
      sep = '|'
      for s in ',+| ':
        if s in params[2]:
          sep = s
          break
      for p in params[2].split(sep):
        perm |= perms[p.upper()]
      with open(f"{config['keystore']}/{keyid.hex()}/servers", 'rb') as fd:
         servers = tomlkit.load(fd)
      return m, keyid, ltsigpub, ltsigkey, params[1], perm, t, servers

   if cmd == import_cfg:
      keyid = pysodium.crypto_generichash(params[0], k=config['id_salt'])
      ltsigkey = getltsigkey()
      ltsigpub = a2b_base64(config['ltsigpub'][8:])
      return keyid, ltsigpub, ltsigkey, params[1]

   if cmd in {listusers, delete}:
      keyid = pysodium.crypto_generichash(params[0], k=config['id_salt'])
      ltsigkey = getltsigkey()
      ltsigpub = a2b_base64(config['ltsigpub'][8:])
      m, keyid, _, _, _, _ = loadmeta(keyid)
      return m, keyid, ltsigpub, ltsigkey

   if cmd == refresh:
      keyid = pysodium.crypto_generichash(params[0], k=config['id_salt'])
      ltsigkey = getltsigkey()
      ltsigpub = a2b_base64(config['ltsigpub'][8:])
      m, keyid, pki, epoch, t, pkis = loadmeta(keyid)
      return m, keyid, ltsigpub, ltsigkey, t, epoch, pki, pkis

   if cmd == deluser:
      keyid = pysodium.crypto_generichash(params[0], k=config['id_salt'])
      ltsigkey = getltsigkey()
      ltsigpub = a2b_base64(config['ltsigpub'][8:])
      m, keyid, _, _, t, _ = loadmeta(keyid)
      with open(f"{config['keystore']}/{keyid.hex()}/servers", 'rb') as fd:
         servers = tomlkit.load(fd)
      return m, keyid, ltsigpub, ltsigkey, params[1]

   if cmd == update:
      delta = sys.stdin.readline()
      if not delta.startswith("KLCDELTA-"): raise ValueError("invalid delta format")
      raw = a2b_base64(delta[9:])
      keyid = raw[:KEYID_SIZE]
      epoch = struct.unpack(">I", raw[KEYID_SIZE:KEYID_SIZE+4])[0]
      delta = raw[KEYID_SIZE+4:]
      delta = pysodium.crypto_core_ristretto255_scalar_invert(delta)
      return keyid, delta, epoch

   if cmd == provision:
      port = "/dev/ttyACM0"
      cfg_file = None
      uart=False
      esp=False
      # parse args
      for arg in params:
         if arg.startswith('/dev/'):
            port=arg
         elif arg.split('/')[-1] in {'klutshnik.cfg', 'config', '.klutshnikrc'}:
            cfg_file = arg
         elif arg.endswith('authorized_keys'):
            with open(arg,'r') as fd:
               authkeys=[line.strip() for line in fd]
         elif arg=='uart':
            import pyudev
            context = pyudev.Context()
            for device in context.list_devices(subsystem='tty'):
                if device.device_node == port:
                    uart=device.get('ID_SERIAL_SHORT')
                    break
         elif arg=="esp":
            esp=True
      with open(cfg_file,'rb') as fd:
          cfg = tomlkit.load(fd)
      return port, cfg_file, cfg, authkeys, uart, esp

def process_result(cmd, ret):
   if cmd == create:
      keyid, epoch, pki, pkis = ret
      savemeta(keyid, pki, pkis, config['threshold'], 0, get_servers())
      print(f"KLCPK-{b2a_base64(keyid+epoch+pki).decode('utf8').strip()}", flush=True)
   elif cmd == adduser:
      b64 = b2a_base64(lzma.compress(ret.encode('utf8'))).decode('utf8').strip()
      if config.get('verbose'):
         print('the newly authorized client must run:\nklutshnik import "some-keyname" ', end='', file=sys.stderr)
      print(f"KLTCFG-{b64}")
   elif cmd == refresh:
      save, keyid, pki, pkis, t, epoch = ret
      if save:
         savemeta(keyid, pki, pkis, t, epoch)
      print(f"KLCPK-{b2a_base64(keyid+struct.pack('>I',epoch)+pki).decode('utf8').strip()}", flush=True)
   elif cmd == rotate:
      keyid, t, epoch, pki, pkis, delta = ret
      savemeta(keyid, pki, pkis, t, epoch)
      print(f"KLCPK-{b2a_base64(keyid+struct.pack('>I',epoch)+pki).decode('utf8').strip()}\n"
            f"KLCDELTA-{b2a_base64(keyid+struct.pack('>I',epoch)+delta).decode('utf8').strip()}", flush=True)

#### main ####

cmds = {'init'     : {'cmd': init,      'params': 2},
        'create'   : {'cmd': create,    'params': 3},
        'rotate'   : {'cmd': rotate,    'params': 3},
        'encrypt'  : {'cmd': encrypt,   'params': 3},
        'decrypt'  : {'cmd': decrypt,   'params': 2},
        'update'   : {'cmd': update,    'params': 2},
        'refresh'  : {'cmd': refresh,   'params': 3},
        'delete'   : {'cmd': delete,    'params': 3},
        'adduser'  : {'cmd': adduser,   'params': 5},
        'deluser'  : {'cmd': deluser,   'params': 4},
        'listusers': {'cmd': listusers, 'params': 3},
        'import'   : {'cmd': import_cfg,'params': 4},
        'provision': {'cmd': provision, 'params': 6},
        }

def main(params=sys.argv):
  if len(params) < 2: usage(params, True)
  if params[1] in ('help', '-h', '--help'):
    usage(params, True)

  if params[1] not in cmds:
    usage(params)

  global config
  config = processcfg(getcfg('klutshnik'))

  #if debug:
  #  import ctypes
  #  libc = ctypes.cdll.LoadLibrary('libc.so.6')
  #  fdopen = libc.fdopen
  #  log_file = ctypes.c_void_p.in_dll(pyoprf.liboprf,'log_file')
  #  fdopen.restype = ctypes.c_void_p
  #  log_file.value = fdopen(2, 'w')

  op = cmds[params[1]]
  if len(params) != op['params']: usage(params)
  cmd =  op['cmd']

  m = None
  ltsigkey = None
  args = getargs(config, cmd, params[2:])
  if cmd not in {encrypt, update, import_cfg, provision}:
     m = args[0]
     ltsigkey = args[3]

  error = None
  try:
    ret = cmd(*args)
  except Exception as exc:
    error = exc
    ret = False
    if m is not None: m.close()
    if debug: raise
  finally:
    if ltsigkey is not None: clearmem(ltsigkey)
    if m is not None: m.close()

  if not ret:
    if not error:
      print("fail", file=sys.stderr)
      sys.exit(3) # error not handled by exception
    print(error, file=sys.stderr)
    sys.exit(1) # generic errors

  if cmd in {create, rotate, refresh} or params[1]=="adduser":
    process_result(cmd, ret)
  elif ret != True:
    print("reached code that should not be reachable: ", ret)

if __name__ == '__main__':
  try:
    main(sys.argv)
  except Exception:
    print("fail", file=sys.stderr)
    if debug: raise # only for dbg
