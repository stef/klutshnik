#!/usr/bin/env python3

import struct, socket
from dissononce.extras.meta.protocol.factory import NoiseProtocolFactory
from dissononce.processing.handshakepatterns.interactive.XK import XKHandshakePattern

class NoiseWrapper():
   @classmethod
   def connect(cls, address, port, privkey, pubkey):
     s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
     s.settimeout(5)
     s.connect((address, port))
     return cls(s, privkey, pubkey)

   def __init__(self, fd, privkey, pubkey):
      self.fd = fd
      protocol = NoiseProtocolFactory().get_noise_protocol('Noise_XK_25519_ChaChaPoly_BLAKE2b')
      handshakestate = protocol.create_handshakestate()

      # initialize handshakestate objects
      handshakestate.initialize(XKHandshakePattern(), True, b'', s=privkey, rs=pubkey)

      # step 1
      message_buffer = bytearray()
      handshakestate.write_message(b'', message_buffer)

      fd.sendall(message_buffer)

      # step 2
      message_buffer = fd.recv(48)
      handshakestate.read_message(bytes(message_buffer), bytearray())

      # step 3
      message_buffer = bytearray()
      self.state = handshakestate.write_message(b'', message_buffer)
      fd.sendall(message_buffer)

   def sendall(self, pkt):
      ct = self.state[0].encrypt_with_ad(b'', pkt)
      msg = struct.pack(">H", len(ct)) + ct
      self.fd.sendall(msg)

   def read_pkt(self,size):
      res = []
      read = 0
      plen = self.fd.recv(2)
      if len(plen)!=2:
          raise ValueError
      plen = struct.unpack(">H", plen)[0]
      while read<plen or len(res[-1])==0:
        res.append(self.fd.recv(plen-read))
        read+=len(res[-1])
      return self.state[1].decrypt_with_ad(b'', b''.join(res))
