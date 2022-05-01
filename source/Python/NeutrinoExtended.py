#!/usr/bin/env python3
'''
Copyright (c) 2021–22 etkaar <https://github.com/etkaar/Neutrino>

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
import math

from Neutrino import Neutrino
from NeutrinoReliable import NeutrinoReliable
from typing import Optional

"""
An extended NeutrinoReliable class to eliminate the packet
size limit of 1280 bytes (Neutrino::MAX_PACKET_SIZE).

Neutrino > NeutrinoReliable > NeutrinoExtended
"""
class NeutrinoExtended(NeutrinoReliable):

	#MAX_PAYLOAD_SIZE: int = 8
	
	# Raise payload size limits
	MAX_AMOUNT_OF_PAYLOAD_WORDS_IN_BYTES: int = 2 # 2 bytes = 2**16-1 = 0–65535
	MAX_PAYLOAD_WORD_SIZE_IN_BYTES: int = 4 # 4 bytes = 2**32-1 = 0–4294967295
	
	MAX_AMOUNT_OF_PAYLOAD_WORDS: int = (2**(8*MAX_AMOUNT_OF_PAYLOAD_WORDS_IN_BYTES) - 1)
	MAX_PAYLOAD_WORD_SIZE: int = (2**(8*MAX_PAYLOAD_WORD_SIZE_IN_BYTES) - 1)

	FORMAT_CHAR_MAX_AMOUNT_OF_PAYLOAD_WORDS: str = 'H' # Unsigned short (2 bytes)
	FORMAT_CHAR_MAX_PAYLOAD_WORD_SIZE: str = 'I' # Unsigned int (4 bytes)

	# Empty to make inheritance easier
	def __init__(self):
		super().__init__()

	"""
	EVENTS: NeutrinoReliable
	"""
	# Once a packet is reliably received (= in order, not a duplicate)
	def reliable_event_on_packet_received(self, client_id: Optional[int], session_id: int, remote_addr_pair: tuple, packet_type: int, packet_number: int, packet_keyword: int, payload_words: tuple) -> None:
		print(">>RELIABLE RECEIVED (EXTENDED)", 'packet_number', packet_number, 'packet_keyword', packet_keyword)
	
	"""
	OVERRIDINGS / EXTENSIONS
	"""
	def _send_packet(self, client_id: Optional[int], session_id: int, remote_addr_pair: Optional[tuple], packet_type: int, packet_number: int, packet_keyword: int, raw_payload_bytes: bytes=None, payload_words: list=[], padding: int=0) -> tuple:
		# Only this class is entitled to manage the packet_keyword parameter
		if packet_keyword is not self.PACKET_KEYWORD_NONE:
			raise NeutrinoExtended.ConflictionError("'packet_keyword' is <{0}> while PACKET_KEYWORD_NONE was expected. This parameter is exclusively managed by this class.".format(packet_keyword))
		
		"""
		Call original function only for specific packet types
		"""
		if packet_type in [self.PACKET_TYPE_CLIENT_HELLO1]:
			return super()._send_packet(client_id, session_id, remote_addr_pair, packet_type, packet_number, packet_keyword, raw_payload_bytes, payload_words, padding)
		
		"""
		All other packet types
		"""
		# Convert byte words list into payload
		if raw_payload_bytes is None:
			raw_payload_bytes = self._byte_words_to_payload(payload_words)
		
		# Calculate payload size
		payload_size = len(raw_payload_bytes)
		
		if payload_size > self.MAX_PAYLOAD_SIZE:
			# Maximum payload size can only be exceeded by data packets
			if packet_type is not self.PACKET_TYPE_DATA:
				raise Neutrino.LogicError("Maximum payload size of {0} bytes can only be exceeded by PACKET_TYPE_DATA, but not for {1} packets.".format(self.MAX_PAYLOAD_SIZE, self.get_packet_name_by_type(packet_type)))
			
			# Same for packets with no packet number
			if packet_number <= self.PACKET_NUMBER_PENDING:
				raise Neutrino.LogicError("Can't exceed payload size if no packet number is given.")
			
		#if payload_size > self.MAX_PAYLOAD_SIZE:
		#	print(">>EXCEEDED", 'self.MAX_PAYLOAD_SIZE', self.MAX_PAYLOAD_SIZE, 'payload_size', payload_size, 'packet_keyword', packet_keyword)
		#print('raw_payload_bytes', raw_payload_bytes)
		
		#payloads = []
		
		number_of_packets_required = math.ceil(payload_size / self.MAX_PAYLOAD_SIZE)
		
		#if number_of_packets_required > 1:
		print('number_of_packets_required', number_of_packets_required)
		
		for part_number in range(number_of_packets_required, 0, -1):
			begin = part_number * self.MAX_PAYLOAD_SIZE
			end = begin + self.MAX_PAYLOAD_SIZE
			
			#payloads.append(raw_payload_bytes[begin:end])
			
			# We need to increment the packet number, if we are required to send multiple packets
			if part_number > 0:
				if self.is_server() is True:
					packet_number = self._get_servers_client_session_packet_number(client_id=client_id, increment=True)
				elif self.is_client() is True:
					packet_number = self._get_clients_packet_number(increment=True)
					
			# Packet keyword is the part number which is (part_number + 1). Therefore, a packet keyword of 0 (= None) means,
			# the payload was not exceeded and only a single packet is required to be received.
			packet_keyword = (part_number - 1)
			
			print('packet_keyword', packet_keyword, 'self.MAX_PACKET_KEYWORD_SIZE', self.MAX_PACKET_KEYWORD_SIZE)
			
			# Call native method to stepwisely send out all parts of the payload (or simply once if size was not exceeded) 
			super()._send_packet(client_id, session_id, remote_addr_pair, packet_type, packet_number, packet_keyword, raw_payload_bytes[begin:end], padding=padding)

			if part_number > 0:
				print(">>SENT OUT part", part_number, 'total payload_size', payload_size, 'packet_type', packet_type, 'packet_keyword', packet_keyword, 'packet_number', packet_number, 'raw_payload_bytes[begin:end]', raw_payload_bytes[begin:end])
	
	# Watch for partial packets and collect their payloads
	def _decode_and_validate_decrypted_packet_header_and_payload(self, raw_packet: bytes) -> tuple:
		# Packet number and keyword
		(packet_number, packet_keyword) = self._decode_and_validate_decrypted_packet_header(raw_packet)
		
		# Full packet; proceed as usual
		#if packet_keyword == self.MAX_PACKET_KEYWORD_SIZE:
		payload_words = self._decode_and_validate_decrypted_packet_payload(raw_packet)
		# Partial packet: Decoding takes place later, so omit decoding at this time
		#else:
			#payload_words = []
			
		return (packet_number, packet_keyword, payload_words)
		
	"""
	NEW EVENTS
	
	Just inherit this class to use events:
	
		> from NeutrinoExtended import NeutrinoExtended
		> class Neutrino(NeutrinoExtended):
		>   def event_*() -> ?:
		>      pass
	"""
	def extended_event_on_packet_received(self, client_id: Optional[int], session_id: int, remote_addr_pair: tuple, packet_type: int, packet_number: int, payload_words: tuple) -> None:
		return

	"""
	EXCEPTIONS
	"""
	class ConflictionError(Exception):
		__module__ = Exception.__module__
		
