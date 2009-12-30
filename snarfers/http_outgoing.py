#!/usr/bin/env python
import re

EMAIL_RE = '[\w].*?[\@\%][\w\.]+'

def Parse(pkt):
  payload = pkt['Raw.load']
  

  # Wordpress
  if 'POST /wp-admin/' in payload:
    match = re.search('Host: ([\w\.]+)', payload)
    if match:
      return ('Blog', 'Wordpress', match.group(1))
      
  # Google Talk
  elif 'gmailchat=' in payload:
    match = re.search('\; gmailchat=(%s)\/' % EMAIL_RE, payload)
    if match:
      return ('Chat', 'Google Talk', match.group(1))

  # GMail
  elif 'GET /mail/' in payload:
    match = re.search('\&gausr=(%s)' % EMAIL_RE, payload)
    if match:
      return ('E-Mail', 'GMail', match.group(1))
      
  # Gravatar
  elif 'gravatar=' in payload:
    match = re.search('Cookie: gravatar=([\w]+)%7C', payload)
    if match:
      return ('Username', 'Gravatar', match.group(1))

  # brizzly.com
  elif 'Brizzly%20%20%2F%20' in payload:
    match = re.search('Brizzly%20%20%2F%20(\w+)%0A', payload)
    if match:
      return ('Username', 'Brizzly', match.group(1))
      
  # Generic e-mail  
  elif '&email=' in payload:
    match = re.search('&email=(%s)' % EMAIL_RE, payload)
    if match:
      return ('E-Mail', 'HTTP POST', match.group(1))

#  match = re.search('User-Agent: ([\w \/\-\.\(\;,:\)]+)', payload)
#  if match:
#    return ('User-Agent', 'HTTP', match.group(1))
  
  return None