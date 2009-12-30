#!/usr/bin/env python

import re

def Parse(pkt):
  """Parse outgoing Yahoo Instant Messenger chats."""
  match = re.search('YMSG.*\xc0\x80(.*)\xc0\x80', pkt['Raw.load'])
  if match:
    return ('Chat', 'Yahoo Instant Messenger', match.group(1))

