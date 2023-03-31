#!/usr/bin/env python
# SPDX-FileCopyrightText: 2023, Marsiske Stefan
# SPDX-License-Identifier: GPL-3.0-or-later

import ctypes, ctypes.util
import pysodium
from klutshnik.noiseclient import NoiseWrapper, connect, gather
from klutshnik.utils import split_by_n

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

def dkg(servers, threshold, noisekey, getauthkey):
   n = len(servers)
   keyid = pysodium.randombytes(KEYID_SIZE)
   conns = connect(servers, DKG, threshold, n, keyid, noisekey, getauthkey(DKG,keyid), VERSION)

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

   return yc.raw, keyid, authtoken

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

def tuokms_stream_decrypt(r, c, d, pubkey, beta, verifier_beta):
   if(kmslib.tuokms_stream_decrypt(0, 1, r, c, d, pubkey, beta, verifier_beta)): raise ValueError

def decrypt(w,pubkey,servers,threshold,keyid, noisekey, getauthkey):
   # first blind w
   r,c,d,a,v = blind(w)
   # send to servers
   n = len(servers)
   conns = connect(servers, Evaluate, threshold, n, keyid, noisekey, getauthkey(Evaluate, keyid), VERSION)

   msg = a + v
   for index,conn in enumerate(conns):
       conn.sendall(msg)

   # receive responses from tuokms_evaluate
   responders=gather(conns, 33*2, n, lambda pkt: (pkt[:33], pkt[33:]))

   xresps = tuple(responders[i][0] for i in range(n))
   vresps = tuple(responders[i][1] for i in range(n))

   # we only select the first t shares, should be rather random
   beta = thresholdmult(threshold, xresps)
   beta_verifier = thresholdmult(threshold, vresps)

   return tuokms_stream_decrypt(r, c, d, pubkey, beta, beta_verifier)

def reconstruct(threshold, shares):
   v = ctypes.create_string_buffer(pysodium.crypto_core_ristretto255_SCALARBYTES)
   kmslib.dkg_reconstruct(threshold, b''.join(shares), v)
   return v.raw

def update(servers,threshold,keyid, noisekey, getauthkey):
   n = len(servers)
   conns = connect(servers, TUOKMS_Update, threshold, n, keyid, noisekey, getauthkey(TUOKMS_Update, keyid), VERSION)

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
