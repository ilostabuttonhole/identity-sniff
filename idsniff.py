#!/usr/bin/env python
#
# Create a list of "who" each user is on a given network by sniffing their
# internet traffic. 

DEFAULT_LISTEN_PORTS = (25, 80, 137, 110, 143, 5050, 5353) 

import sys
import optparse
from scapy.all import sniff, IP, TCP, UDP, NBNSQueryRequest, load_module
from snarfers import http_outgoing
from snarfers import http_incoming
from snarfers import yahoo_outgoing
from snarfers import mdns_outgoing
from snarfers import upnp_outgoing
from snarfers import netbios_ns_outgoing

load_module("p0f")

class IdentitySniffer(object):
  def __init__(self, interface=None, pcap_filename=None, filter=None):
    """Create a IdentitySniffer
    
    Args:
      interface: interface name to sniff on
      pcap_filename: tcpdump output to process
      filter: pcap filter to use when capturing data
    """    
    self.interface = interface
    self.filter = filter
    self.pcap_filename = pcap_filename
    
  def ProcessPacket(self, pkt):
    """Packet processing callback.
    
    Args:
      scapy.Packet
    """
    results = None
    p0f_results = None
    if not pkt.haslayer(IP):
      return
 
    src_or_dst = 'src'
    # TCP packets only so far
    if pkt.getlayer(IP).proto == 6:
      if pkt.getlayer(TCP).flags & 0x13 == 0x02:
        p0f_results = p0f(pkt)
        print "p0f: %s" % p0f_results
  
      if 'Raw' not in pkt:
        return
      if pkt.getlayer(TCP).dport == 80:
        # SYN
        results = http_outgoing.Parse(pkt)
      elif pkt.getlayer(TCP).sport == 80:
        src_or_dst = 'dst'
        results = http_incoming.Parse(pkt)
      elif pkt.getlayer(TCP).dport == 5050:
        results = yahoo_outgoing.Parse(pkt)
      
    # UDP
    elif pkt.getlayer(IP).proto == 17:
      if pkt.getlayer(UDP).dport == 137:
        if pkt.haslayer(NBNSQueryRequest):
          results = netbios_ns_outgoing.Parse(pkt)
      elif pkt.getlayer(UDP).dport == 5353:
        results = mdns_outgoing.Parse(pkt)
      elif pkt.getlayer(UDP).dport == 1900:
        results = upnp_outgoing.Parse(pkt)

    if results:
      output = [pkt['Ethernet'].fields[src_or_dst], pkt.getlayer(IP).fields[src_or_dst], p0f_results] + list(results) 
      print output
    else:
      if 'Raw' not in pkt:
        return
      payload = pkt['Raw.load']      
      # TODO(tstromberg): Remove hardcoded test data.
      matched = False
      for word in ('helixblue', 'Sallad', 'Dallas', 'Thomas', 'Stromberg', 'tjourney', 'Dell', 'Core2'):
        if word in payload:
          matched = True
          print 'Missed: %s' % payload

      if matched:
        print pkt.summary()

  def ProcessInput(self):
    """Call this when you are ready for IdentitySniffer to do something."""

    print "filter: %s" % self.filter
    if self.interface:
      sniff(prn=self.ProcessPacket, store=0, filter=self.filter, iface=self.interface)      
    elif self.pcap_filename:
      sniff(prn=self.ProcessPacket, store=0, offline=self.pcap_filename)
    else:
      sniff(prn=self.ProcessPacket, store=0, filter=self.filter)

if __name__ == '__main__':
  # For the time-being, we only accept pcap data as an argument.
  parser = optparse.OptionParser()
  parser.add_option('-r', '--file', dest='pcap_filename', default=None,
                    type='str', help='Path to pcap file to parse')
  parser.add_option('-i', '--interface', dest='interface', default=None,
                    type='str', help='Ethernet interface to use')
  (options, args) = parser.parse_args()
  if args:
    filter = args[0]
  else:
    filter = 'port %s' % ' or port '.join(map(str, DEFAULT_LISTEN_PORTS))
  ids = IdentitySniffer(pcap_filename=options.pcap_filename, interface=options.interface, filter=filter)
  ids.ProcessInput()
