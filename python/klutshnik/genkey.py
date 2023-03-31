#!/usr/bin/env python
 
from dissononce.dh.x25519.x25519 import X25519DH
import sys
import binascii

def main():
  # setup initiator and responder variables
  keypair = X25519DH().generate_keypair()
  
  with open(sys.argv[1], 'wb') as fd:
      fd.write(keypair.private.data)
  
  print(binascii.b2a_base64(keypair.public.data).decode("utf8"))

if __name__ == '__main__':
  main()
