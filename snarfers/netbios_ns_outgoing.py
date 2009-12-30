#!/usr/bin/env python

import re

def Parse(pkt):
  """Parse outgoing netbios-ns messages."""
  answer = pkt.QUESTION_NAME.replace(' ', '')
  if pkt.SUFFIX == 16974 or pkt.SUFFIX == 16972:
    return ('Workgroup', 'NetBIOS', answer)
  elif pkt.SUFFIX == 16705:
    return ('Machine Name', 'NetBIOS', answer)


