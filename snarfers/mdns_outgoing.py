#!/usr/bin/env python

import re

def Parse(pkt):
  """Parse MDNS broadcasts"""
  match = re.search('model=([\w+,]+)', pkt['Raw.load'])
  if match:
    return ('Machine Model', 'MDNS', match.group(1))

  match = re.search('Machine Name=([\w\'\, ]+)', pkt['Raw.load'])
  if match:
    return ('Machine Name', 'MDNS', match.group(1))

