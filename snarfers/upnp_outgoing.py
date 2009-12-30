#!/usr/bin/env python

import re

def Parse(pkt):
  """Parse UPNP broadcasts"""
  match = re.search('Server:(.*?) ', pkt['Raw.load'])
  if match:
    return ('Operating System', 'UPNP', match.group(1))
