#!/usr/bin/env python
# Copyright (c) 2010 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Wrapper around
   third_party/WebKit/Tools/Scripts/new-run-webkit-httpd"""
import os
import subprocess
import sys

def main():
    cmd = [sys.executable]
    src_dir=os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(
                         os.path.dirname(os.path.abspath(sys.argv[0]))))))
    script_dir=os.path.join(src_dir, "third_party", "WebKit", "Tools",
                            "Scripts")
    script = os.path.join(script_dir, 'new-run-webkit-httpd')
    cmd.append(script)
    cmd.extend(sys.argv[1:])
    return subprocess.call(cmd)

if __name__ == '__main__':
    sys.exit(main())
