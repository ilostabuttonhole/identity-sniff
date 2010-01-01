import re
import gzip
import zlib
import StringIO
from scapy.all import hexdump, TCP, IP

EMAIL_RE = '[\w].*?[\@\%][\w\.]+'

CONTENT_FRAGMENTS = {}

def _Decompress(data):
  """Decompress gzipped data."""
#  print hexdump(data)
  compressed_stream = StringIO.StringIO(data)
  decompressor = gzip.GzipFile(fileobj=compressed_stream)
  try:
    extracted = decompressor.read()
  except:
    raise IOError
  return extracted

def _AttemptGzipResponseReassembly(pkt):
  payload = str(pkt[TCP].payload)
  decompressed = False
  frag_id = '.'.join(map(str, [pkt[IP].fields['src'],
                     pkt[TCP].sport,
                     pkt[IP].fields['dst'],
                     pkt[TCP].dport]))

  if 'Content-Encoding: gzip' in payload:
    content_location = payload.find('\r\n\r\n')
    match = re.search('Content-Length: (\d+)', payload, re.MULTILINE)
    if match:
      content_size = match.group(1)
      print "CONTENT SIZE: %s" % content_size
    else:
      print "!!!!!!!!! NO CONTENT-SIZE in %s" % payload[:content_location]
      
    if content_location > 0:
      gzip_content = payload[content_location+4:]
      try:
        decompressed = _Decompress(gzip_content)
        return decompressed
      except IOError, zlib.error:
        CONTENT_FRAGMENTS[frag_id] = [gzip_content]
        print "- Found truncated gzipped content: Began %s" % frag_id
  else:
    if frag_id in CONTENT_FRAGMENTS:
      CONTENT_FRAGMENTS[frag_id].append(payload)
      try_content = ''.join(CONTENT_FRAGMENTS[frag_id])
#      print hexdump(try_content)
      try:
        decompressed = _Decompress(try_content)
        print '- Extracted %s (%s bytes, %s elements)' % (frag_id, len(try_content), len(CONTENT_FRAGMENTS[frag_id]))
        del CONTENT_FRAGMENTS[frag_id]
        return decompressed
      except IOError, zlib.error:
        pass
        print '- Unable to extract %s (%s bytes, %s elements)' % (frag_id, len(try_content), len(CONTENT_FRAGMENTS[frag_id]))


def Parse(pkt):
  decompressed = _AttemptGzipResponseReassembly(pkt)
  if decompressed:
    content = decompressed
  else:
    content = str(pkt[TCP].payload)
  
  # Used by Google
  # {"userId":"17739266793723263052","userName":"helixblue","userProfileId":"116119420122834839490","userEmail":"helixblue@gmail.com","isBloggerUser":true,"signupTimeSec":0,"publicUserName":"helixblue"}
  match = re.search('"userEmail":"(.*?)"', content)
  if match:
    return ('E-Mail', 'GMail', match.group(1))

  # Used by Google
  match = re.search('&uj=(.*?)\&', content)
  if match:
    return ('Login', 'Google', match.group(1))

  # Used by Twitter
  match = re.search('<meta content="(.*?)" name="session-user-screen_name" />', content)
  if match:
    return ('Username', 'Twitter', match.group(1))
  
  # Used by Flickr
  # <a class="block" href="/photos/helixblue/" id="personmenu_your_photos_link">Your Photostream</a>
  match = re.search('href="/photos/(\w+)/" id="personmenu_your_photos_link', content)
  if match:
    return ('Username', 'Flickr', match.group(1))
  
  # Used by Picasaweb
  match = re.search('/lh/people?uname=(\w+)&amp;isOwner=true', content)
  if match:
    return ('Username', 'Picasaweb', match.group(1))
  
  # 'authUserNickname':'Thomas Stromberg',
  match = re.search("'authUserNickname':'(.*?)',", content)
  if match:
    return ('Name', 'Picasaweb', match.group(1))
  
  # - helixblue's YouTube
  match = re.search("- (\w+)'s  YouTube", content)
  if match:
    return ('Username', 'YouTube', match.group(1))
 
  # UtilLinks/Username');">helixblue</a>
  match = re.search("UtilLinks\/Username\'\)\;\"\>(.*?)\<\/a\>", content)
  if match:
    return ('Username', 'YouTube', match.group(1))
 
  # <a href="http://www.facebook.com/dstromberg?ref=name" class="fb_menu_link">Dallas Str<C3><B6>mberg</a>
  match = re.search("ref=name\" class=\"fb_menu_link\">(.*?)\<\/a\>", content)
  if match:
    return ('Name', 'Facebook Menu-Link', match.group(1))

  # "uri":"http:\/\/www.facebook.com\/dstromberg?ref=profile","title":"Facebook | Dallas Str\u00f6mberg"
  match = re.search('ref=profile","title":"Facebook \| (.*?)"', content)
  if match:
    return ('Name', 'Facebook Profile Link', match.group(1))
    
  # <div class=\"profile_name_and_status\"><h1 id=\"profile_name\">Dallas Str\u00f6mberg<\/h1>
  match = re.search('profile_name_and_status.*?\<h1 id=.*?profile_name.*?>(.*?)\<.*?h1', content)
  if match:
    return ('Name', 'Facebook Name/Status', match.group(1))

  # <div id=guser width=100%><nobr><b>helixblue@gmail.com</b>
  match = re.search("div id=guser width=100%\>\<nobr\>\<b\>(.*?\@.*?)\<\/b\>", content)
  if match:
    return ('Username', 'Google', match.group(1))

  # ,["cfs",[["Dallas Stromberg","dallas@stromberg.org",1,""]
  # D(["cfs",[["Thomas StrC6mberg","thomas@stromberg.org",1,""]
  match = re.search('\["cfs",\[\["(.*?)","(.*?\@.*?)",1,""\]', content)
  if match:
    user_data = '%s <%s>' % (match.group(1), match.group(2))
    return ('Name/E-Mail', 'GMail JSON', user_data)

  # ,["ugn","Dallas Stromberg"]
  # (["ugn","Thomas Stromberg"]
  match = re.search(',\["ugn","(.*?)"\]', content)
  if match:
    return ('Name', 'GMail JSON', match.group(1))
    
  # Help out
  if decompressed:
    for word in ('mberg',):
      if word in content:
        print 'Missed: %s' % content
