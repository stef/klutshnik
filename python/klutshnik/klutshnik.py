#!/usr/bin/env python3

# SPDX-FileCopyrightText: 2018-2021, Marsiske Stefan
# SPDX-License-Identifier: GPL-3.0-or-later

import sys, os, struct, io
import pysodium, pyoprf
from klutshnik.cfg import getcfg
from SecureString import clearmem
from pyoprf.multiplexer import Multiplexer
from binascii import a2b_base64, b2a_base64
from itertools import zip_longest

import ctypes, ctypes.util
klutshniklib = ctypes.cdll.LoadLibrary(ctypes.util.find_library('klutshnik') or
                                 ctypes.util.find_library('libklutshnik.so') or
                                 ctypes.util.find_library('libklutshnik') or
                                 ctypes.util.find_library('libklutshnik0'))
if not klutshniklib._name:
   raise ValueError('Unable to find libklutshnik')

KEYID_SIZE = pysodium.crypto_generichash_BYTES

#### consts ####

CREATE  =b'\x00'
ROTATE  =b'\x33'
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
    try:
        server['ssl_cert'] = os.path.expanduser(server.get('ssl_cert')) # only for dev, production system should use proper certs!
    except TypeError: # ignore exception in case ssl_cert is not set, thus None is attempted to expand.
        server['ssl_cert'] = None

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

def savekey(keyid, pubkey, pkis, threshold):
  keyid = keyid.hex()
  with open(f"{config['keystore']}/{keyid}", 'wb') as fd:
    fd.write(bytes([threshold, len(pkis)]))
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

def loadkey(keyid):
  keyid=keyid.hex()
  try:
    with open(f"{config['keystore']}/{keyid}", 'rb') as fd:
      threshold = int(fd.read(1)[0])
      n = int(fd.read(1)[0])
      pki = fd.read(pysodium.crypto_core_ristretto255_BYTES)
      pkis = readall(fd, (pysodium.crypto_core_ristretto255_BYTES+1) * n)
      return pki, threshold, pkis
  except FileNotFoundError:
    raise ValueError("unknown keyid")

#### OPs ####

def create(m, keyid):
  op = CREATE
  n = len(m)
  t = config['threshold']
  ts_epsilon=config['ts_epsilon']

  # load peer long-term keys
  with open(config['ltsigpub'],'rb') as fd:
    sig_pks = [fd.read()]

  for name, server in config['servers'].items():
    with open(server.get('ltsigkey'),'rb') as fd:
      peer_lt_pk = fd.read()
      if(len(peer_lt_pk)!=pysodium.crypto_sign_PUBLICKEYBYTES):
        raise ValueError(f"long-term signature key for server {name} is of incorrect size")
      sig_pks.append(peer_lt_pk)

  with open(config['ltsigkey'],'rb') as fd:
    sig_sks = fd.read()

  stp, msg0 = pyoprf.stp_dkg_start_stp(n, t, ts_epsilon, "klutshnik v1.0 stp dkg", sig_pks, sig_sks)
  for i, peer in enumerate(m):
    pkid = pysodium.crypto_generichash(str(i).encode('utf8') + keyid)
    m.send(i, op+pkid+msg0)

  while pyoprf.stp_dkg_stp_not_done(stp):
    cur_step = pyoprf.stp_dkg_stpstate_step(stp)
    ret, sizes = pyoprf.stp_dkg_stp_input_sizes(stp)
    #print(f"step: {cur_step} {ret} {sizes}", file=sys.stderr)
    peer_msgs = []
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
    #print(f"outlen: {len(out)}", file=sys.stderr)
    if(len(out)>0):
      for i in range(pyoprf.stp_dkg_stpstate_n(stp)):
        msg = pyoprf.stp_dkg_stp_peer_msg(stp, out, i)
        #print(f"sending({i} {m[i].name}({m[i].address}), {msg.hex()})", file=sys.stderr)
        send_pkt(m, msg, i)

  pkis = tuple(p for p in m.gather(33) if p is not None)
  if len(pkis) != n:
    raise ValueError("only {len(pkis)} out of {n} peers responded with their pubkey shares")
  pki = pyoprf.thresholdmult(pkis[:t])
  savekey(keyid, pki, pkis, t)

  auth0 = sig_pks[0] + b'\x4f'
  sig = pysodium.crypto_sign_detached(auth0,sig_sks)
  for i in range(len(m)):
    send_pkt(m, sig+auth0, i)

  return f"pk {b2a_base64(pki).decode('utf8').strip()}"

def rotate(m, keyid, force=False):
  op = ROTATE
  n = len(m)
  t = config['threshold']
  ts_epsilon=config['ts_epsilon']

  # load peer long-term keys
  with open(config['ltsigpub'],'rb') as fd:
    sig_pks = [fd.read()]

  for name, server in config['servers'].items():
    with open(server.get('ltsigkey'),'rb') as fd:
      peer_lt_pk = fd.read()
      if(len(peer_lt_pk)!=pysodium.crypto_sign_PUBLICKEYBYTES):
        raise ValueError(f"long-term signature key for server {name} is of incorrect size")
      sig_pks.append(peer_lt_pk)

  with open(config['ltsigkey'],'rb') as fd:
    sig_sks = fd.read()

  stp, msg0 = pyoprf.tupdate_start_stp(n, t, ts_epsilon, "klutshnik update", sig_pks, keyid, sig_sks)
  for i, peer in enumerate(m):
    pkid = pysodium.crypto_generichash(str(i).encode('utf8') + keyid)
    m.send(i, op+pkid+msg0+sig_pks[0])

  auth(m, keyid, [msg0+sig_pks[0]] * len(m))

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

  pkis = tuple(p for p in m.gather(33) if p is not None)
  if len(pkis) != n:
    raise ValueError("only {len(pkis)} out of {n} peers responded with their pubkey shares")
  pki = pyoprf.thresholdmult(pkis[:t])
  savekey(keyid, pki, pkis, t)

  return b2a_base64(delta).decode('utf8').strip()

def encrypt(keyid):
   yc, _, _ = loadkey(keyid)
   os.write(1, keyid)
   klutshniklib.klutshnik_stream_encrypt(yc, 0, 1)
   return True

def decrypt(m):
  with open(config['ltsigpub'],'rb') as fd:
    sigpk = fd.read()

  keyid = os.read(0, KEYID_SIZE)
  pubkey, t, pkis = loadkey(keyid)

  w = os.read(0, pysodium.crypto_core_ristretto255_BYTES)
  if not pysodium.crypto_core_ristretto255_is_valid_point(w): raise ValueError("w value is invalid")

  r = pysodium.crypto_core_ristretto255_scalar_random()
  a = pysodium.crypto_scalarmult_ristretto255(r, w)

  c = pysodium.crypto_core_ristretto255_scalar_random()
  v = pysodium.crypto_scalarmult_ristretto255(c, w)
  d = pysodium.crypto_core_ristretto255_scalar_random()
  tmp = pysodium.crypto_scalarmult_ristretto255_base(d)
  v = pysodium.crypto_core_ristretto255_add(v, tmp)

  # send to servers
  msg = a + v
  for i, peer in enumerate(m):
    pkid = pysodium.crypto_generichash(str(i).encode('utf8') + keyid)
    m.send(i, DECRYPT+pkid+msg+sigpk)

  auth(m, keyid, [msg+sigpk] * len(m))

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

def update(keyid, delta):
  delta = a2b_base64(delta)
  delta = pysodium.crypto_core_ristretto255_scalar_invert(delta)
  for path in sys.stdin:
    path = path.strip()
    with open(path,'r+b') as fd:
        fkeyid = fd.read(KEYID_SIZE)
        if keyid!=fkeyid:
            if config.get('verbose'): print(f"{path} is not encrypted using keyid: {args.keyid}, skipping")
            continue
        w = fd.read(pysodium.crypto_core_ristretto255_BYTES)
        w = pysodium.crypto_scalarmult_ristretto255(delta, w)
        fd.seek(-pysodium.crypto_core_ristretto255_BYTES,io.SEEK_CUR)
        fd.write(w)
  return True

def delete(m, keyid, force=False):
  # load peer long-term keys
  with open(config['ltsigpub'],'rb') as fd:
    sigpk = fd.read()

  for i, peer in enumerate(m):
    pkid = pysodium.crypto_generichash(str(i).encode('utf8') + keyid)
    m.send(i, DELETE+pkid+sigpk)

  auth(m, keyid, [sigpk] * len(m))

  ret = True
  resps = m.gather(2)
  for i, r in enumerate(resps):
    if r != b'ok':
      print(f"failed to delete on {m[i].name}")
      ret = False

  os.unlink(f"{config['keystore']}/{keyid.hex()}")

  return ret

def auth(m, keyid, reqbufs):
  sizes = tuple(p for p in m.gather(2) if struct.unpack(">H", p)[0] != 32)
  if sizes != tuple(): raise ValueError("failed to receive auth nonces")

  nonces = tuple(p for p in m.gather(32) if p is not None)
  if len(nonces) != len(m):
    raise ValueError("only {len(nonces)} out of {len(m)} peers responded with auth nonces")

  with open(config['ltsigkey'],'rb') as fd:
    sk = fd.read()

  for i, nonce in enumerate(nonces):
    pkid = pysodium.crypto_generichash(str(i).encode('utf8') + keyid)
    resp = pysodium.crypto_sign_detached(pkid+reqbufs[i]+nonce,sk)
    send_pkt(m, resp, i)

  clearmem(sk)

def adminauth(m, keyid, op, pubkey=None, rights=None):
  if op!='list':
    pubkey = a2b_base64(pubkey)

  if op=='add':
    perm = 0
    sep = '|'
    for s in ',+| ':
      if s in rights:
        sep = s
        break
    for p in rights.split(sep):
      perm |= perms[p.upper()]

  opcode = b'\x00' if op != 'list' else b'\x01'

  for i, peer in enumerate(m):
    pkid = pysodium.crypto_generichash(str(i).encode('utf8') + keyid)
    m.send(i, MODAUTH+pkid+opcode)

  auth(m, keyid, [opcode] * len(m))

  sizes = tuple(struct.unpack(">H", p)[0] for p in m.gather(2) if p is not None)
  if len(sizes) != len(m): raise ValueError("failed to receive auth blob sizes")
  if len(set(sizes)) != 1: raise ValueError("received inconsistent auth blob sizes")
  size = tuple(set(sizes))[0]

  authblobs = tuple(p for p in m.gather(size) if p is not None)
  if len(authblobs) != len(m): raise ValueError("failed to receive auth blob sizes")
  if len(set(authblobs)) != 1: raise ValueError("received inconsistent auth blob sizes")

  with open(config['ltsigpub'],'rb') as fd:
    pk = fd.read()
  authblob = tuple(set(authblobs))[0]

  sig = authblob[:pysodium.crypto_sign_BYTES]
  data = authblob[pysodium.crypto_sign_BYTES:]
  try:
    pysodium.crypto_sign_verify_detached(sig, data, pk)
  except:
    raise ValueError("invalid signature on authblob")

  items = {bytes(e[:32]): e[32]&0xf for e in split_by_n(data, pysodium.crypto_sign_PUBLICKEYBYTES+1)}
  if op == 'list':
    for pk, p in items.items():
        print(pk.hex(), perm_str[p])
    return True

  if op=='add':
    if config.get('verbose') and items.get(pubkey) == perm:
      print(f"{pk.hex()} already has perm ({items.get(pubkey)} == {perm}): {perm_str[perm]}")
    items[pubkey]=perm
  elif op=='del':
    if config.get('verbose') and items.get(pubkey) is None:
      print(f"cannot delete {pk.hex()}, it is not authorized at all")
    else:
      del items[pubkey]

  auth2 = b''.join(k+bytes([p]) for k,p in items.items())

  with open(config['ltsigkey'],'rb') as fd:
    sig_sks = fd.read()
  sig = pysodium.crypto_sign_detached(auth2,sig_sks)
  clearmem(sig_sks)
  msg = sig+auth2
  for i in range(len(m)):
    send_pkt(m, msg, i)

  return True

def usage(params, help=False):
  print("usage: %s " % params[0])
  print("     %s create  <keyid>" % params[0])
  print("     %s encrypt <keyid>" % params[0])
  print("     %s decrypt"         % params[0])
  print("     %s rotate  <keyid>" % params[0])
  print("     %s delete  <keyid>" % params[0])
  print("     %s update  <keyid> <delta>  <files2update" % params[0])

  if help: sys.exit(0)
  sys.exit(100)

#### main ####

cmds = {'create'   : {'cmd': create,    'net': True,  'params': 3},
        'rotate'   : {'cmd': rotate,    'net': True,  'params': 3},
        'encrypt'  : {'cmd': encrypt,   'net': False, 'params': 3},
        'decrypt'  : {'cmd': decrypt,   'net': True,  'params': 2},
        'update'   : {'cmd': update,    'net': False, 'params': 4},
        'delete'   : {'cmd': delete,    'net': True,  'params': 3},
        'adduser'  : {'cmd': adminauth, 'net': True,  'params': 5},
        'deluser'  : {'cmd': adminauth, 'net': True,  'params': 4},
        'listusers': {'cmd': adminauth, 'net': True,  'params': 3},
        }

def main(params=sys.argv):
  if len(params) < 2: usage(params, True)
  cmd = None
  args = []
  if params[1] in ('help', '-h', '--help'):
    usage(params, True)

  if params[1] not in cmds:
    usage(params)

  op = cmds[params[1]]

  #if params[1] == "genltsigkey":
  #    sys.exit(genltsigkey(*params[2:]))

  global config
  config = processcfg(getcfg('klutshnik'))
  if debug:
    import ctypes
    libc = ctypes.cdll.LoadLibrary('libc.so.6')
    fdopen = libc.fdopen
    log_file = ctypes.c_void_p.in_dll(pyoprf.liboprf,'log_file')
    fdopen.restype = ctypes.c_void_p
    log_file.value = fdopen(2, 'w')

  if len(params) != op['params']: usage(params)
  cmd =  op['cmd']

  if op['net']:
    s = Multiplexer(config['servers'])
    s.connect()
    args.append(s)

  if cmd != decrypt:
    args.append(pysodium.crypto_generichash(params[2], k=config['id_salt']))

  if cmd == update:
    args.append(params[3])

  if params[1] == "adduser":
    args.append('add')
    args.extend(params[3:5])
  elif params[1] == "deluser":
    args.append('del')
    args.append(params[3])
  elif params[1] == "listusers":
    args.append('list')

  error = None
  try:
    ret = cmd(*args)
  except Exception as exc:
    error = exc
    ret = False
    if debug: raise
  if op['net']:
    s.close()

  if not ret:
    if not error:
      print("fail", file=sys.stderr)
      sys.exit(3) # error not handled by exception
    print(error, file=sys.stderr)
    sys.exit(1) # generic errors

  if cmd in {create, rotate}:
    print(ret)
    sys.stdout.flush()
  elif ret != True:
    print("reached code that should not be reachable: ", ret)

if __name__ == '__main__':
  try:
    main(sys.argv)
  except Exception:
    print("fail", file=sys.stderr)
    if debug: raise # only for dbg
