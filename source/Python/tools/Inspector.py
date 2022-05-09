#!/usr/bin/env python3
'''
Copyright (c) 2022 etkaar <https://github.com/etkaar/Neutrino>

Restriction (Standard OSPAA 1.0): Only for legal entities with a yearly
revenue exceeding fifty (50) million US-Dollar (or an equivalent of) the
license text below is valid with the exception, that in modification of
the license, for any right granted there (especially the use, modification
and distribution) the author has the right of fair compensation which must
be individually agreed. Is the legal entity part of a multinational company,
the total revenue of all corporations counts. This restriction does not
apply to non-profit organizations. This text must be included in all
copies or substantial portions of the source code.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR
OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE
OR OTHER DEALINGS IN THE SOFTWARE.
'''

'''
	Requirements / Dependencies
	  - Python >= 3.7
	    - Scapy
	       apt install python3-scapy
	    - NetfilterQueue (https://github.com/oremanj/python-netfilterqueue)
		   apt install python3-pip
	       apt install libnfnetlink-dev libnetfilter-queue-dev
		   
		   pip3 install NetfilterQueue
		   
		   For installation problems, see:
		     https://github.com/oremanj/python-netfilterqueue/issues/53#issuecomment-567705281
'''
import os
import sys

DIRNAME = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(1, os.path.abspath(DIRNAME + '/..'))

import struct

from scapy.layers.inet import IP
from scapy.layers.inet import UDP

from netfilterqueue import NetfilterQueue

from Neutrino import Neutrino

"""
The Inspector is a great helper for testing purposes. The firewall
grabs Neutrino packets and redirects them to the Inspector. He can
then independently inspect, delay, delete, duplicate or alter them.

Firewall

  - nftables
     insert rule inet filter default_input position 0 udp dport 22753 counter queue num 0 bypass
	
	  'bypass' makes sure that packets are not redirected to the queue if Inspector is not running.
	  'position' is at 0 to make sure packets are not accidentially handled (accepted and forgotten) by another rule.
	  'dport' is the default port of Neutrino.
	  'queue num' the number of the queue the Inspector uses.
"""
class Inspector:
	"""
	CONSTANTS: COMMON
	"""
	QUEUE_NUMBER: int = 0
	
	def __init__(self):
		self.neutrino = Neutrino()
		
	# Wait for packets passed through the queue
	def start_investigating(self) -> None:
		nfqueue = NetfilterQueue()
		nfqueue.bind(self.QUEUE_NUMBER, self.handle_packet)

		try:
			nfqueue.run()
		except KeyboardInterrupt:
			pass
	
	# Handles a single packet from the queue.
	def handle_packet(self, raw_ip_packet: bytes) -> None:
		"""
		We need to extract the UDP payload (= Neutrino packet) from the lower IP packet.
		
		  ... > IP > (UDP | TCP) > Neutrino
		  https://infosys.beckhoff.com/english.php?content=../content/1033/bk9053_bk9103/2792604555.html&id=
		"""
		ip_payload = IP(raw_ip_packet.get_payload())
		udp_payload = bytes(ip_payload[UDP].payload)
		
		# Unprotected left part
		left_unprotected = udp_payload[0:Neutrino.HEADER_SIZE_LEFT]
		
		# Encrypted right part which contains packet_number, packet_keyword and payload_words
		right_encrypted = udp_payload[Neutrino.HEADER_SIZE_LEFT:]
		
		# Decode the whole left unprotected part of the Neutrino packet header
		(protocol_identifier, protocol_version, packet_type, session_id) = self.neutrino._unpack(Neutrino.HEADER_FORMAT_LEFT, left_unprotected)
		
		"""
		Here the packet can be altered.
		"""
		# Malform header values
		if False:
			protocol_identifier += 1
			
		if False:
			protocol_version += 1
			
		if False:
			packet_type += 1
			
		if False:
			session_id +=1
		
		# Change length of the encrypted part
		if True:
			right_encrypted = right_encrypted[1:]
		
		# Rebuild the packet
		new_udp_payload = b''
		new_udp_payload += self.neutrino._pack(Neutrino.HEADER_FORMAT_LEFT, protocol_identifier, protocol_version, packet_type, session_id)
		new_udp_payload += right_encrypted
		
		# Update UDP payload
		ip_payload[UDP].remove_payload()
		ip_payload[UDP].add_payload(new_udp_payload)
		
		# Trigger recalculation of the checksums
		del ip_payload[IP].chksum
		del ip_payload[IP].len
		
		del ip_payload[UDP].chksum
		del ip_payload[UDP].len
	
		# Update IP payload
		raw_ip_packet.set_payload(bytes(ip_payload))
	
		# Do not drop packet
		raw_ip_packet.accept()

# Do not execute if imported as module
if __name__ == '__main__':
	inspector = Inspector()
	inspector.start_investigating()
