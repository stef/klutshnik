#!/usr/bin/env python

import os
import sys

TPL_HEAD = """
verbose = true
threshold = 3
key="../config/client.key"
keystore="keys"
authtok="%s"

[servers]
"""

TPL_KMS = """
[servers.%s]
host="%s"
port=10000
pubkey="%s"

"""

d = sys.argv[1]

authtok = open(os.path.join(d, "godmode.b64"),"r").read().strip()

cfg = TPL_HEAD % (authtok)


for filename in os.listdir(d):
    if filename.endswith(".pub"):
        kms_name = filename.split(".")[0]
        pubkey = open(os.path.join(d, filename),"r").read().strip()
        ip = open(os.path.join(d, "%s.ip" % (kms_name)), "r").read().strip()
        tpl = TPL_KMS % (kms_name, ip, pubkey)
        cfg += tpl

print(cfg)        
