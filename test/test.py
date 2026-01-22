import unittest
from os import listdir, path, environ
from pathlib import Path
from shutil import rmtree
from io import BytesIO, StringIO
import sys, subprocess, time, os, tempfile, struct, lzma
from klutshnik import klutshnik
from klutshnik.cfg import getcfg
import tracemalloc
from pyoprf import multiplexer
import contextlib
from binascii import a2b_base64, b2a_base64

# to get coverage, run
# PYTHONPATH=.. coverage run test.py
# coverage report -m
# to just run the tests do
# python3 -m unittest discover --start-directory .

keyid = b"keyid"
otherkeyid = b"importedkeyid"
data = b"data1"

def wrapio(msg):
  r_out, w_out = os.pipe()
  r_in, w_in = os.pipe()

  stdin = os.dup(0)
  stdout = os.dup(1)
  os.dup2(r_in, 0)
  os.dup2(w_out, 1)

  # pt expected on stdin
  os.write(w_in, msg)
  return (r_out, w_out, r_in, w_in, stdin, stdout)

def unwrapio(ctx, size):
  r_out, w_out, r_in, w_in, stdin, stdout = ctx
  # ct on stdout
  if size>0:
    res = os.read(r_out, size)
  else:
    res = None
  os.dup2(stdin, 0)
  os.dup2(stdout, 1)

  os.close(r_out)
  os.close(w_out)
  os.close(r_in)
  os.close(w_in)
  os.close(stdout)
  os.close(stdin)
  return res

class Input:
  def __init__(self, txt = None):
    self.ptr = 0
    if txt is None:
      self.buffer = BytesIO(data)
    else:
      self.buffer = BytesIO(txt)
  def isatty(self):
      return False
  def close(self):
    return
  def readline(self):
    return self.buffer.readline().decode('utf8')
  def __iter__(self):
    return self
  def __next__(self):
    r = self.readline()
    if r != '': return r
    raise StopIteration

def clean_dir(d):
  if not path.exists(d): return
  #os.write(2, f"rm -rf {d}\n".encode('utf8'))
  for f in listdir(d):
    p = Path(os.path.join(d,f))
    if p.is_symlink() or p.is_file():
      p.unlink()
    elif p.is_dir():
      try: rmtree(p)
      except OSError as e:
        if e.strerror == "Directory not empty":
          # Not sure why this happens, but trying again seems to fix it usually?
          rmtree(p)
        else:
          raise

test_path = path.dirname(path.abspath(__file__))
c, cfg_files = getcfg('klutshnik')
klutshnik.config = klutshnik.processcfg(c)
klutshnik.config['clientkey_path']="client.key"

def connect(peers=None):
  if peers == None:
    peers = klutshnik.config['servers']
  m = multiplexer.Multiplexer(peers)
  m.connect()
  return m

def create(kid):
  m, kid, ltsigpub, ltsigkey, t, ts_epsilon, sig_pks = klutshnik.getargs(klutshnik.config, klutshnik.create, [kid], cfg_files)
  k_id, epoch, pki, pkis = klutshnik.create(m, kid, ltsigpub, ltsigkey, t, ts_epsilon, sig_pks)
  m.close()
  klutshnik.savemeta(k_id, pki, pkis, klutshnik.config['threshold'], 0, klutshnik.get_servers())
  return k_id, epoch, pki, pkis

def decrypt(ct):
  ctx = wrapio(ct)
  m, kid, ltsigpub, ltsigkey, t, epoch, pki, pkis = klutshnik.getargs(klutshnik.config, klutshnik.decrypt, [], cfg_files)
  klutshnik.decrypt(m, kid, ltsigpub, ltsigkey, t, epoch, pki, pkis)
  m.close()
  return unwrapio(ctx, len(ct)-96)

def refresh():
  m, kid, ltsigpub, ltsigkey, t, lepoch, lpki, lpkis = klutshnik.getargs(klutshnik.config, klutshnik.refresh, [keyid], cfg_files)
  save, kid, pki, pkis, t, epoch = klutshnik.refresh(m, kid, ltsigpub, ltsigkey, t, lepoch, lpki, lpkis)
  m.close
  if save:
    klutshnik.savemeta(kid, pki, pkis, t, epoch)
  return save

def rotate(keyid):
  m, kidr0, ltsigpub, ltsigkey, t, ts_epsilon, sig_pks, lepoch = klutshnik.getargs(klutshnik.config, klutshnik.rotate, [keyid], cfg_files)
  kidr1, t, epoch, pki, pkis, delta = klutshnik.rotate(m, kidr0, ltsigpub, ltsigkey, t, ts_epsilon, sig_pks, lepoch)
  klutshnik.savemeta(kidr1, pki, pkis, t, epoch)
  return (f"KLCDELTA-{b2a_base64(kidr1+struct.pack('>I',epoch)+delta).decode('utf8').strip()}",
          f"KLCPK-{b2a_base64(kidr1+struct.pack('>I',epoch)+pki).decode('utf8').strip()}")

def update(ct, delta):
  fd, name = tempfile.mkstemp()
  os.write(fd, ct)
  os.close(fd)

  stdin = sys.stdin
  sys.stdin = Input(f"{delta}\n{name}".encode("utf8"))
  kidu, delta, epoch_u = klutshnik.getargs(klutshnik.config, klutshnik.update, [], cfg_files)
  klutshnik.update(kidu, delta, epoch_u)
  sys.stdin = stdin
  with open(name, 'rb') as fd:
    ct_u = fd.read()
  os.unlink(name)
  return ct_u

def adduser(pk, perms):
  params = [keyid, pk, perms]
  m, kid, ltsigpub, ltsigkey, userpub, perm, t, servers = klutshnik.getargs(klutshnik.config, klutshnik.adduser, params, cfg_files)
  xprt = klutshnik.adduser(m, kid, ltsigpub, ltsigkey, userpub, perm, t, servers)
  m.close()
  return f"KLTCFG-{b2a_base64(lzma.compress(xprt.encode('utf8'))).decode('utf8').strip()}"

class TestEndToEnd(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
      #import ctypes
      #libc = ctypes.cdll.LoadLibrary('libc.so.6')
      #log_file = ctypes.c_void_p.in_dll(klutshnik.pyoprf.liboprf,'liboprf_log_file')
      #fdopen = libc.fdopen
      #fdopen.restype = ctypes.c_void_p
      #log_file.value = fdopen(2, 'w')
      #debug = ctypes.c_int.in_dll(klutshnik.pyoprf.liboprf,'liboprf_debug')
      #debug = 1

      cls._oracles = []
      clean_dir('keystore')
      clean_dir('otherclient/keystore')
      klutshnikd = environ.get("KLUTSHNIKD", "../../../server/zig-out/bin/klutshnikd")
      for idx in range(len(klutshnik.config['servers'])):
        clean_dir(f"{test_path}/servers/{idx}/data/")
        log = open(f"{test_path}/servers/{idx}/log", "w")
        cls._oracles.append(
          (subprocess.Popen(klutshnikd, cwd = f"{test_path}/servers/{idx}/", stdout=log, stderr=log, pass_fds=[log.fileno()]), log))
        log.close()

        ddir = f"{test_path}/servers/{idx}/data/"
        clean_dir(ddir)
      time.sleep(0.8)

    @classmethod
    def tearDownClass(cls):
      for p, log in cls._oracles:
        p.kill()
        r = p.wait()
        log.close()
      time.sleep(0.4)

    def tearDown(self):
      time.sleep(0.1)
      clean_dir('keystore')
      clean_dir('otherclient/keystore')
      for idx in range(len(klutshnik.config['servers'])):
        ddir = f"{test_path}/servers/{idx}/data/"
        clean_dir(ddir)

    def test_0010_create(self):
      kid, epoch, pki, pkis = create(keyid)
      self.assertEqual(len(pkis), 5)
      self.assertIsInstance(pki, bytes)
      self.assertEqual(b'\x00\x00\x00\x00', epoch)

    def test_0020_create_2x(self):
      kid, epoch, pki, pkis = create(keyid)
      self.assertEqual(len(pkis), 5)
      self.assertIsInstance(pki, bytes)
      self.assertEqual(b'\x00\x00\x00\x00', epoch)
      with connect() as s:
        self.assertRaises(ValueError, create, keyid)

    def test_0030_decrypt(self):
      k_id, epoch, pki, pkis = create(keyid)

      pk = f"KLCPK-{b2a_base64(k_id+epoch+pki).decode('utf8').strip()}"
      kid, pk = klutshnik.getargs(klutshnik.config, klutshnik.encrypt, [pk], cfg_files)

      # start encrypt stdin/out fuckery
      ctx = wrapio(data)
      klutshnik.encrypt(kid, pk)
      ct = unwrapio(ctx, 1000)

      # start decrypt stdin/out fuckery
      self.assertEqual(data, decrypt(ct))

    def test_0040_rotate(self):
      k_id, epoch, pki, pkis = create(keyid)

      pk = f"KLCPK-{b2a_base64(k_id+epoch+pki).decode('utf8').strip()}"
      kid, pk = klutshnik.getargs(klutshnik.config, klutshnik.encrypt, [pk], cfg_files)

      # start encrypt stdin/out fuckery
      ctx = wrapio(data)
      klutshnik.encrypt(kid, pk)
      ct = unwrapio(ctx, 1000)

      # start decrypt stdin/out fuckery
      self.assertEqual(data, decrypt(ct))

      delta_txt, npk = rotate(keyid)

      ct_u = update(ct, delta_txt)
      self.assertEqual(data, decrypt(ct_u))

    def test_0050_list_owner(self):
      k_id, epoch, pki, pkis = create(keyid)
      # list key owner

      m, kid, ltsigpub, ltsigkey = klutshnik.getargs(klutshnik.config, klutshnik.listusers, [keyid], cfg_files)
      output = StringIO()
      stdout = sys.stdout
      sys.stdout = output

      try:
        klutshnik.listusers(m, kid, ltsigpub, ltsigkey)
      finally:
        sys.stdout = stdout

      # Get the printed output
      self.assertEqual(output.getvalue().strip(), f"{ltsigpub.hex()} owner,decrypt,update,delete")

    def test_0060_add_user(self):
      k_id, epoch, pki, pkis = create(keyid)

      # add a user
      userpk ='Nx+2tXa6AO2l08jADqkXOsCYVv+r1x4IL7gQKoPKKZ9tsAGpvy5S6ZKYlnjbkeVaSXxtKK3Iuj177vQpW5h2dQ=='
      perms = 'decrypt,update'
      adduser(userpk, perms)

      # list users

      m, kid, ltsigpub, ltsigkey = klutshnik.getargs(klutshnik.config, klutshnik.listusers, [keyid], cfg_files)
      output = StringIO()
      stdout = sys.stdout
      sys.stdout = output

      try:
        klutshnik.listusers(m, kid, ltsigpub, ltsigkey)
      finally:
        sys.stdout = stdout

      # Get the printed output
      self.assertEqual(output.getvalue().strip(),
                       f"{ltsigpub.hex()} owner,decrypt,update,delete\n"
                       f"{a2b_base64(userpk)[:32].hex()} {perms}")

    def test_0070_decrypt_other_user(self):
      k_id, epoch, pki, pkis = create(keyid)

      pk = f"KLCPK-{b2a_base64(k_id+epoch+pki).decode('utf8').strip()}"
      kid, pk = klutshnik.getargs(klutshnik.config, klutshnik.encrypt, [pk], cfg_files)

      # start encrypt stdin/out fuckery
      ctx = wrapio(data)
      klutshnik.encrypt(kid, pk)
      ct = unwrapio(ctx, 1000)

      # add a user
      userpk ='Nx+2tXa6AO2l08jADqkXOsCYVv+r1x4IL7gQKoPKKZ9tsAGpvy5S6ZKYlnjbkeVaSXxtKK3Iuj177vQpW5h2dQ=='
      perms = 'decrypt,update'
      xprt=adduser(userpk, perms)

      # import the key owners data to the new user
      orig_config = klutshnik.config
      cwd = os.getcwd()
      os.chdir("otherclient")
      try:
        c, cfg_files2 = getcfg('klutshnik')
        klutshnik.config = klutshnik.processcfg(c)
        klutshnik.masterkey = None

        # import owners key related metada
        params = [otherkeyid, xprt]
        kid, ltsigpub, ltsigkey, export = klutshnik.getargs(klutshnik.config, klutshnik.import_cfg, params, cfg_files2)
        klutshnik.import_cfg(kid, ltsigpub, ltsigkey, export)

        # decrypt
        self.assertEqual(data, decrypt(ct))

      finally:
        klutshnik.config = orig_config
        klutshnik.masterkey = None
        os.chdir(cwd)

    def test_0080_update_other_user(self):
      k_id, epoch, pki, pkis = create(keyid)

      pk = f"KLCPK-{b2a_base64(k_id+epoch+pki).decode('utf8').strip()}"
      kid, pk = klutshnik.getargs(klutshnik.config, klutshnik.encrypt, [pk], cfg_files)

      # start encrypt stdin/out fuckery
      ctx = wrapio(data)
      klutshnik.encrypt(kid, pk)
      ct = unwrapio(ctx, 1000)

      # add a user
      userpk ='Nx+2tXa6AO2l08jADqkXOsCYVv+r1x4IL7gQKoPKKZ9tsAGpvy5S6ZKYlnjbkeVaSXxtKK3Iuj177vQpW5h2dQ=='
      perms = 'decrypt,update'
      xprt=adduser(userpk, perms)

      # import the key owners data to the new user
      orig_config = klutshnik.config
      cwd = os.getcwd()
      os.chdir("otherclient")
      try:
        c, cfg_files2 = getcfg('klutshnik')
        klutshnik.config = klutshnik.processcfg(c)
        klutshnik.masterkey = None

        # import owners key related metada
        params = [otherkeyid, xprt]
        kid, ltsigpub, ltsigkey, export = klutshnik.getargs(klutshnik.config, klutshnik.import_cfg, params, cfg_files2)
        klutshnik.import_cfg(kid, ltsigpub, ltsigkey, export)

        delta_txt, npk = rotate(otherkeyid)

        ct_u = update(ct, delta_txt)

        # decrypt
        self.assertEqual(data, decrypt(ct_u))

      finally:
        klutshnik.config = orig_config
        klutshnik.masterkey = None
        os.chdir(cwd)

    def test_0090_unauth_delete(self):
      # create key
      k_id, epoch, pki, pkis = create(keyid)

      # add a user
      userpk ='Nx+2tXa6AO2l08jADqkXOsCYVv+r1x4IL7gQKoPKKZ9tsAGpvy5S6ZKYlnjbkeVaSXxtKK3Iuj177vQpW5h2dQ=='
      perms = 'decrypt,update'
      xprt=adduser(userpk, perms)

      # import the key owners data to the new user
      orig_config = klutshnik.config
      cwd = os.getcwd()
      os.chdir("otherclient")
      try:
        c, cfg_files2 = getcfg('klutshnik')
        klutshnik.config = klutshnik.processcfg(c)
        klutshnik.masterkey = None

        # import owners key related metada
        params = [otherkeyid, xprt]
        kid, ltsigpub, ltsigkey, export = klutshnik.getargs(klutshnik.config, klutshnik.import_cfg, params, cfg_files2)
        klutshnik.import_cfg(kid, ltsigpub, ltsigkey, export)

        # delete key
        m, kid, ltsigpub, ltsigkey = klutshnik.getargs(klutshnik.config, klutshnik.delete, [otherkeyid], cfg_files)
        self.assertFalse(klutshnik.delete(m, kid, ltsigpub, ltsigkey))
        m.close()

      finally:
        klutshnik.config = orig_config
        klutshnik.masterkey = None
        os.chdir(cwd)

    def test_0100_del_user(self):
      k_id, epoch, pki, pkis = create(keyid)

      # add a user
      userpk ='Nx+2tXa6AO2l08jADqkXOsCYVv+r1x4IL7gQKoPKKZ9tsAGpvy5S6ZKYlnjbkeVaSXxtKK3Iuj177vQpW5h2dQ=='
      perms = 'decrypt,update'
      xprt=adduser(userpk, perms)

      # list users

      m, kid, ltsigpub, ltsigkey = klutshnik.getargs(klutshnik.config, klutshnik.listusers, [keyid], cfg_files)
      output = StringIO()
      stdout = sys.stdout
      sys.stdout = output

      try:
        klutshnik.listusers(m, kid, ltsigpub, ltsigkey)
      finally:
        sys.stdout = stdout

      # Get the printed output
      self.assertEqual(output.getvalue().strip(),
                       f"{ltsigpub.hex()} owner,decrypt,update,delete\n"
                       f"{a2b_base64(userpk)[:32].hex()} {perms}")

      # deluser
      params = [keyid, userpk]
      m, kid, ltsigpub, ltsigkey, pubkey = klutshnik.getargs(klutshnik.config, klutshnik.deluser, params, cfg_files)
      klutshnik.deluser(m, kid, ltsigpub, ltsigkey, pubkey)
      m.close()

      # list users
      m, kid, ltsigpub, ltsigkey = klutshnik.getargs(klutshnik.config, klutshnik.listusers, [keyid], cfg_files)
      output = StringIO()
      stdout = sys.stdout
      sys.stdout = output

      try:
        klutshnik.listusers(m, kid, ltsigpub, ltsigkey)
      finally:
        sys.stdout = stdout

      # Get the printed output
      self.assertEqual(output.getvalue().strip(), f"{ltsigpub.hex()} owner,decrypt,update,delete")

    def test_0110_decrypt_deleted(self):
      k_id, epoch, pki, pkis = create(keyid)

      pk = f"KLCPK-{b2a_base64(k_id+epoch+pki).decode('utf8').strip()}"
      kid, pk = klutshnik.getargs(klutshnik.config, klutshnik.encrypt, [pk], cfg_files)

      # start encrypt stdin/out fuckery
      ctx = wrapio(data)
      klutshnik.encrypt(kid, pk)
      ct = unwrapio(ctx, 1000)

      # delete key
      m, kid, ltsigpub, ltsigkey = klutshnik.getargs(klutshnik.config, klutshnik.delete, [keyid], cfg_files)
      self.assertTrue(klutshnik.delete(m, kid, ltsigpub, ltsigkey))
      m.close()

      # start decrypt stdin/out fuckery
      self.assertRaises(ValueError, decrypt, ct)

    def test_0120_delete_other_deleted(self):
      k_id, epoch, pki, pkis = create(keyid)

      pk = f"KLCPK-{b2a_base64(k_id+epoch+pki).decode('utf8').strip()}"
      kid, pk = klutshnik.getargs(klutshnik.config, klutshnik.encrypt, [pk], cfg_files)

      # start encrypt stdin/out fuckery
      ctx = wrapio(data)
      klutshnik.encrypt(kid, pk)
      ct = unwrapio(ctx, 1000)

      # add a user
      userpk ='Nx+2tXa6AO2l08jADqkXOsCYVv+r1x4IL7gQKoPKKZ9tsAGpvy5S6ZKYlnjbkeVaSXxtKK3Iuj177vQpW5h2dQ=='
      perms = 'decrypt,update'
      xprt=adduser(userpk, perms)

      # import the key owners data to the new user
      orig_config = klutshnik.config
      cwd = os.getcwd()
      os.chdir("otherclient")
      try:
        c, cfg_files2 = getcfg('klutshnik')
        klutshnik.config = klutshnik.processcfg(c)
        klutshnik.masterkey = None

        # import owners key related metada
        params = [otherkeyid, xprt]
        kid, ltsigpub, ltsigkey, export = klutshnik.getargs(klutshnik.config, klutshnik.import_cfg, params, cfg_files2)
        klutshnik.import_cfg(kid, ltsigpub, ltsigkey, export)
      finally:
        klutshnik.config = orig_config
        klutshnik.masterkey = None
        os.chdir(cwd)

      # owner deletes key
      m, kid, ltsigpub, ltsigkey = klutshnik.getargs(klutshnik.config, klutshnik.delete, [keyid], cfg_files)
      self.assertTrue(klutshnik.delete(m, kid, ltsigpub, ltsigkey))
      m.close()

      # other user tries to use key that they don't know is deleted
      orig_config = klutshnik.config
      cwd = os.getcwd()
      os.chdir("otherclient")
      try:
        # decrypt
        self.assertRaises(ValueError, decrypt, ct)

      finally:
        klutshnik.config = orig_config
        os.chdir(cwd)

    def test_0130_decrypt_other_user_updated(self):
      # owner creates
      k_id, epoch, pki, pkis = create(keyid)

      pk = f"KLCPK-{b2a_base64(k_id+epoch+pki).decode('utf8').strip()}"
      kid, pk = klutshnik.getargs(klutshnik.config, klutshnik.encrypt, [pk], cfg_files)

      # start encrypt stdin/out fuckery
      ctx = wrapio(data)
      klutshnik.encrypt(kid, pk)
      ct = unwrapio(ctx, 1000)

      # add a user
      userpk ='Nx+2tXa6AO2l08jADqkXOsCYVv+r1x4IL7gQKoPKKZ9tsAGpvy5S6ZKYlnjbkeVaSXxtKK3Iuj177vQpW5h2dQ=='
      perms = 'decrypt,update'
      xprt=adduser(userpk, perms)

      # import the key owners data to the new user
      orig_config = klutshnik.config
      cwd = os.getcwd()
      os.chdir("otherclient")
      try:
        c, cfg_files2 = getcfg('klutshnik')
        klutshnik.config = klutshnik.processcfg(c)
        klutshnik.masterkey = None

        # import owners key related metada
        params = [otherkeyid, xprt]
        kid, ltsigpub, ltsigkey, export = klutshnik.getargs(klutshnik.config, klutshnik.import_cfg, params, cfg_files2)
        klutshnik.import_cfg(kid, ltsigpub, ltsigkey, export)

        # other user rotates
        delta_txt, npk = rotate(otherkeyid)

        # other user updates
        ct_u = update(ct, delta_txt)

      finally:
        klutshnik.config = orig_config
        klutshnik.masterkey = None
        os.chdir(cwd)

      # decrypt without refresh must fail
      self.assertRaises(ValueError, decrypt, ct_u)

      # refresh
      self.assertTrue(refresh())

      # 2nd refresh
      self.assertFalse(refresh())

      # decrypt
      self.assertEqual(data, decrypt(ct_u))

if __name__ == '__main__':
  unittest.main()
