#!/usr/bin/env python3
'''
Copyright (c) 2021–26 etkaar <https://github.com/etkaar/Neutrino>

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

import exceptions.ExceptionsBase as ExBase
import exceptions.ExceptionsReliable as ExReliable
import exceptions.ExceptionsReliableExtended as ExReliableExtended

"""
An extended NeutrinoReliable class to eliminate the packet
size limit of 1280 bytes (Neutrino::MAX_PACKET_SIZE).

Neutrino > NeutrinoReliable > NeutrinoReliableExtended
"""
class NeutrinoReliableExtended(NeutrinoReliable):

	# Raise payload size limits
	MAX_AMOUNT_OF_PAYLOAD_WORDS_IN_BYTES: int = 2 # 2 bytes = 2**16-1 = 0–65535
	MAX_PAYLOAD_WORD_SIZE_IN_BYTES: int = 4 # 4 bytes = 2**32-1 = 0–4294967295
	
	MAX_AMOUNT_OF_PAYLOAD_WORDS: int = (2**(8*MAX_AMOUNT_OF_PAYLOAD_WORDS_IN_BYTES) - 1) # 65535
	MAX_PAYLOAD_WORD_SIZE: int = (2**(8*MAX_PAYLOAD_WORD_SIZE_IN_BYTES) - 1) # 4294967295

	FORMAT_CHAR_MAX_AMOUNT_OF_PAYLOAD_WORDS: str = 'H' # Unsigned short (2 bytes)
	FORMAT_CHAR_MAX_PAYLOAD_WORD_SIZE: str = 'I' # Unsigned int (4 bytes)

	"""
	VARIABLES: NETWORK
	"""
	# ...
	buffer_incomplete_packet: dict = {}

	# Empty to make inheritance easier
	def __init__(self):		
		super().__init__()
	
	"""
	EVENTS: Neutrino
	"""
	# Reset buffer before session establishment
	def base_client_event_on_request_session(self) -> None:
		super().base_client_event_on_request_session()
		
		self.buffer_incomplete_packet = {}
		
	# Delete buffer for client
	def base_server_event_on_client_unregistered(self, reason: int, client_id: int, session_id: int, client_ip: str, client_port: int) -> None:
		super().base_server_event_on_client_unregistered(reason, client_id, session_id, client_ip, client_port)

		# Can be undefined if server refused to answer to the client (see CLIENT_UNREGISTER_REASON_REFUSED)
		if client_id in self.buffer_incomplete_packet:
			del self.buffer_incomplete_packet[client_id]
	
	"""
	EVENTS: NeutrinoReliable
	"""
	# Once a packet is reliably received (= in order, not a duplicate)
	def reliable_event_on_packet_received(self, client_id: Optional[int], session_id: int, remote_addr_pair: tuple, raw_packet: bytes, packet_type: int, packet_number: int, packet_keyword: int, payload_words: list) -> None:
		super().reliable_event_on_packet_received(client_id, session_id, remote_addr_pair, raw_packet, packet_type, packet_number, packet_keyword, payload_words)
		
		# The actual client id or None for the server (converted to -1)
		endpoint_id = client_id or -1
		
		if endpoint_id not in self.buffer_incomplete_packet:
			self.buffer_incomplete_packet[endpoint_id] = {
				'payload': b''
			}
		
		# Remove header from packet and append payload to cache
		self.buffer_incomplete_packet[endpoint_id]['payload'] += raw_packet[self.TOTAL_HEADER_SIZE:]
		
		# Either a single packet with the full payload or the last packet of a series
		if packet_keyword is self.PACKET_KEYWORD_NONE or packet_keyword == 1:
			# Fake header
			raw_packet = self.TOTAL_HEADER_SIZE * b'\x00' + self.buffer_incomplete_packet[endpoint_id]['payload']
			
			# Decode the full raw payload to payload words
			payload_words = self._decode_and_validate_decrypted_packet_payload(raw_packet)
		
			# Clear buffer
			self.buffer_incomplete_packet[endpoint_id]['payload'] = b''
		
			# Trigger event
			self.reliable_extended_event_on_packet_received(client_id, session_id, remote_addr_pair, raw_packet, packet_type, packet_number, payload_words)
			
		return
	
	"""
	OVERRIDINGS / EXTENSIONS
	"""
	def _send_packet(self, client_id: Optional[int], session_id: int, remote_addr_pair: Optional[tuple], packet_type: int, packet_number: int, packet_keyword: int, raw_payload_bytes: bytes=None, payload_words: list=[], padding: int=0) -> tuple:
		raise ExBase.LogicError("'packet_keyword' has to be PACKET_KEYWORD_NONE, as this parameter is exclusively used by this class.".format(packet_keyword))
		# We raise the packet size only for data packets
		if packet_type is not self.PACKET_TYPE_DATA:
			return super()._send_packet(client_id, session_id, remote_addr_pair, packet_type, packet_number, packet_keyword, raw_payload_bytes, payload_words, padding)
		
		# Only this class is entitled to manage the packet_keyword parameter
		if packet_keyword is not self.PACKET_KEYWORD_NONE:
			raise ExBase.LogicError("'packet_keyword' has to be PACKET_KEYWORD_NONE, as this parameter is exclusively used by this class.".format(packet_keyword))
		
		# Convert byte words list into payload
		if raw_payload_bytes is None:
			raw_payload_bytes = self._byte_words_to_payload(payload_words)

		# Total size of payload
		payload_size = len(raw_payload_bytes)
		
		# Calculate amount of total packets required to transmit this payload size
		number_of_packets_required = math.ceil(payload_size / self.MAX_PAYLOAD_SIZE)
		
		# Full payload in a single packet
		if number_of_packets_required == 1:
			return super()._send_packet(client_id, session_id, remote_addr_pair, packet_type, packet_number, packet_keyword, raw_payload_bytes, payload_words, padding)
		else:
			# NOTE: stop is non-including: range(start, stop[, step])
			for part_number in range(0, number_of_packets_required):
				begin = part_number * self.MAX_PAYLOAD_SIZE
				end = begin + self.MAX_PAYLOAD_SIZE
				
				# We need to increment the packet number, if we are required to send multiple packets
				if part_number > 0:
					if self.is_server() is True:
						packet_number = self._get_servers_client_session_packet_number(client_id=client_id, increment=True)
					elif self.is_client() is True:
						packet_number = self._get_clients_packet_number(increment=True)
						
				# We use the packet_keyword for the payload part number
				packet_keyword = (number_of_packets_required - part_number)
				
				# Call native method to stepwisely send out all parts of the payload (or simply once if size was not exceeded) 
				super()._send_packet(client_id, session_id, remote_addr_pair, packet_type, packet_number, packet_keyword, raw_payload_bytes[begin:end], padding=padding)
	
	# We do suppress any encoding of multi-packet payloads here.
	# This takes place before the base_event_on_packet_received() event.
	def _decode_and_validate_decrypted_packet_payload(self, raw_packet: bytes) -> list:
		# Packet number and keyword
		(packet_number, packet_keyword) = self._decode_and_validate_decrypted_packet_header(raw_packet)
		
		#print('>>> _decode_and_validate_decrypted_packet_payload >>>', 'packet_number', packet_number, 'packet_keyword', packet_keyword)
		
		if packet_keyword > 0:
			return []
			
		return super()._decode_and_validate_decrypted_packet_payload(raw_packet)
		
	"""
	NEW EVENTS
	
	Just inherit this class to use events:
	
		> from NeutrinoReliableExtended import NeutrinoReliableExtended
		> class Neutrino(NeutrinoReliableExtended):
		>   def event_*() -> ?:
		>      pass
	"""
	def reliable_extended_event_on_packet_received(self, client_id: Optional[int], session_id: int, remote_addr_pair: tuple, raw_packet: bytes, packet_type: int, packet_number: int, payload_words: list) -> None:
		return
		
