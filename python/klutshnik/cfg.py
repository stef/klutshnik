#!/usr/bin/env python
# SPDX-FileCopyrightText: 2023, Marsiske Stefan
# SPDX-License-Identifier: GPL-3.0-or-later

import os, tomlkit

def getcfg(name, cwd="."):
  files = set()
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
        files.add(path)
    except FileNotFoundError:
        continue
    config.update(data)
  return config, files
