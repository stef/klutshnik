#!/usr/bin/env python
# SPDX-FileCopyrightText: 2023, Marsiske Stefan
# SPDX-License-Identifier: GPL-3.0-or-later

import os, tomlkit

def split_by_n(obj, n):
  # src https://stackoverflow.com/questions/9475241/split-string-every-nth-character
  return [obj[i:i+n] for i in range(0, len(obj), n)]

def getcfg(name, cwd="."):
  paths=[
      # read global cfg
      f'/etc/{name}/config',
      # update with per-user configs
      os.path.expanduser(f"~/.{name}rc"),
      os.path.expanduser(f"~/.config/{name}/config"),
      # over-ride with local directory config
      os.path.expanduser('/'.join([cwd,f"{name}.cfg"]))
  ]
  config = tomlkit.toml_document.TOMLDocument()
  for path in paths:
    try:
        with open(path, "rb") as f:
            data = tomlkit.load(f)
    except FileNotFoundError:
        continue
    config.update(data)
  return config
