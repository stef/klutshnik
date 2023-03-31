#!/usr/bin/env python
# SPDX-FileCopyrightText: 2023, Marsiske Stefan
# SPDX-License-Identifier: GPL-3.0-or-later

import os, tomllib

def split_by_n(obj, n):
  # src https://stackoverflow.com/questions/9475241/split-string-every-nth-character
  return [obj[i:i+n] for i in range(0, len(obj), n)]

def getcfg(name):
  paths=[
      # read global cfg
      f'/etc/{name}/config',
      # update with per-user configs
      os.path.expanduser(f"~/.{name}rc"),
      # over-ride with local directory config
      os.path.expanduser(f"~/.config/{name}/config"),
      os.path.expanduser(f"{name}.cfg")
  ]
  config = dict()
  for path in paths:
    try:
        with open(path, "rb") as f:
            data = tomllib.load(f)
    except FileNotFoundError:
        continue
    config.update(data)
  return config
