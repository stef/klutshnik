#!/usr/bin/env python
# SPDX-FileCopyrightText: 2023, Marsiske Stefan
# SPDX-License-Identifier: GPL-3.0-or-later


import os, io, sys
import pysodium, argparse, subprocess
from binascii import unhexlify, a2b_base64, b2a_base64
from dissononce.dh.x25519.keypair import KeyPair
from dissononce.dh.x25519.public import PublicKey
from klutshnik.noiseclient import NoiseWrapper
from opaquestore import opaquestore

from klutshnik.utils import getcfg
from klutshnik.wrapper import dkg, update, decrypt, stream_encrypt, update_w, DKG, Evaluate, TUOKMS_Update, KEYID_SIZE

config = None

def getpwd(title):
    proc=subprocess.Popen(['/usr/bin/pinentry', '-g'], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err = proc.communicate(input=('SETTITLE klutshnik password prompt\nSETDESC %s\nSETPROMPT opaque-store password\ngetpin\n' % (title)).encode())
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

def savekey(keyid, pubkey, threshold):
   with open(f"{config['keystore']}/{keyid}", 'wb') as fd:
      fd.write(bytes([threshold]))
      fd.write(pubkey)

def loadkey(keyid):
   with open(f"{config['keystore']}/{keyid}", 'rb') as fd:
      threshold = int(fd.read(1)[0])
      return fd.read(), threshold

def processcfg(config):
  with open(config['key'],'rb') as fd:
     config['key']=KeyPair.from_bytes(a2b_base64(fd.read()))

  config['servers'] = [(v.get('host',"localhost"),
                        v.get('port'),
                        PublicKey(a2b_base64(v['pubkey']))) 
                       for k,v in config.get('servers',{}).items()]

  if 'authkey' in config:
    config['authkey']=a2b_base64(config['authkey']+'==')

  if 'opaque-storage' not in config:
        raise ValueError("no opaque-storage and no authkey in config file")

  config['opaque-storage']['noise_key']=KeyPair.from_bytes(a2b_base64(config['opaque-storage']['noise_key']+'=='))
  config['opaque-storage']['server_pubkey']=PublicKey(a2b_base64(config['opaque-storage']['server_pubkey']+'=='))
  opaquestore.config = config['opaque-storage']

  return config

def authkey(op, keyid):
  return config.get('authkey') or getauthkey(op, keyid)

def main(params=sys.argv):
    global config
    config = processcfg(getcfg("klutshnik"))

    parser = argparse.ArgumentParser(description='klutshnik cli'
    f"usage: {sys.argv[0]} -c <genkey|encrypt|decrypt|update>"
    f"       {sys.argv[0]} -c genkey -t threshold ..."
    f"       {sys.argv[0]} -c encrypt -k keyid <filetoencrypt >encryptedfile"
    f"       {sys.argv[0]} -c decrypt <filetodecrypt >decryptedfile"
    f"       {sys.argv[0]} -c update -k keyid <listoffilestoupdate")

    parser.add_argument('-c', '--cmd', choices={"genkey", "encrypt", "decrypt", "update", 'authkey'})
    parser.add_argument('-t', '--threshold', type=int)
    parser.add_argument('-k', '--keyid')
    args = parser.parse_args()

    if args.cmd=="genkey":
        if args.threshold*2 + 1 < len(config['servers']):
            print("Warning this key will not be updatable.", file=sys.stderr)
            print("You need to have at least 2*threshold+1 servers for updatable keys", file=sys.stderr)
            if input("press y/Y to continue") not in ('y','Y'): return
        pubkey, keyid, auth_token = dkg(config['servers'], args.threshold, config['key'], authkey)

        setauthkey(keyid,auth_token)
        if 'opaque-storage' not in config:
          print("authtoken for new key: ", b2a_base64(auth_token).decode('utf8').strip())

        savekey(keyid.hex(), pubkey, args.threshold)
        print("keyid", keyid.hex())

    elif args.cmd=="encrypt":
        pubkey, _ = loadkey(args.keyid)
        os.write(1, unhexlify(args.keyid))
        stream_encrypt(pubkey)

    elif args.cmd=="decrypt":
        keyid = os.read(0, KEYID_SIZE)
        w = os.read(0, pysodium.crypto_core_ristretto255_BYTES)
        pubkey, threshold = loadkey(keyid.hex())
        decrypt(w, pubkey, config['servers'], threshold, keyid, config['key'], authkey)

    elif args.cmd=="update":
        _, threshold = loadkey(args.keyid)
        pubkey, delta = update(config['servers'], threshold, unhexlify(args.keyid), config['key'], authkey)
        savekey(args.keyid, pubkey, threshold)
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
  try:
    main(sys.argv)
  except Exception:
    print("fail", file=sys.stderr)
    raise # only for dbg

