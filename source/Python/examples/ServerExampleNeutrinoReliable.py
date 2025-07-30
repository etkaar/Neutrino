#!/usr/bin/env python3
'''
Copyright (c) 2021–25 etkaar <https://github.com/etkaar/Neutrino>

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
import os
import sys

DIRNAME = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(1, os.path.abspath(DIRNAME + '/..'))

# Don't create *.pyc files
sys.dont_write_bytecode = True

# Other modules
import time
import secrets

from typing import Optional

# Monitoring of the traffic
from Monitoring import Monitoring

# Basic Neutrino class
from NeutrinoReliable import NeutrinoReliable as Neutrino

class Networking(Monitoring, Neutrino):
	"""
	CONSTANTS: COMMANDS
	"""
	# Server
	SERVER_REQUEST_MULTIPLY: int = 0x176
	
	# Client
	CLIENT_RESPONSE_MULTIPLY: int = 0x276
	
	"""
	VARIABLES
	"""
	last_timeframe: int = 0
	
	def __init__(self):
		self.last_timeframe = self._get_current_time_milliseconds()

	"""
	LOCAL FUNCTIONS
	"""
	# Do something each n milliseconds
	def each_timeframe(self, milliseconds: int) -> bool:
		if self.last_timeframe > 0 and self.last_timeframe + milliseconds < self._get_current_time_milliseconds():
			self.last_timeframe = self._get_current_time_milliseconds()
			
			return True
			
		return False
	
	# Converts UTF-8 strings into payload words which must be bytes.
	#
	# It depends on your application how strict you handle encoding errors
	# due to data which originates from user input. If you don't use any
	# data from user input you usually want use <errors='strict'>.
	#
	# NOTE: The list is globally changed, thus pass a copy with 'payload_words[:]'
	# instead of 'payload_words' if you want to keep the original list unchanged.
	def encode_payload_words(self, payload_words: list=[]) -> list:
		for x in range(len(payload_words)):
			if type(payload_words[x]) is not str:
				payload_words[x] = str(payload_words[x])
			
			payload_words[x] = payload_words[x].encode(encoding='utf-8', errors='strict')
			
		return payload_words
	
	# Same into the other direction
	def decode_payload_words(self, payload_words: list=[]) -> list:
		for x in range(len(payload_words)):
			payload_words[x] = payload_words[x].decode(encoding='utf-8', errors='strict')
			
		return payload_words
		
	# Random integer for example command
	def get_random_int(self, min: int, max: int) -> int:
		return self._get_random_int(min, max)
	
	"""
	EVENTS
	"""
	def base_server_event_on_session_request(self, client_id: int, session_id: int, client_ip: str, client_port: int) -> bool:
		super().base_server_event_on_session_request(client_id, session_id, client_ip, client_port)
		
		# Return False to refuse the connection to client
		return True
		
	def base_event_on_requested_frame(self, frame_number: int, milliseconds_between_frames: int) -> None:
		super().base_event_on_requested_frame(frame_number, milliseconds_between_frames)

		# The time between frames can be < 1 ms. So we do that only all two seconds.
		if self.each_timeframe(2000):
			payload_words = []
			
			# With this example command the client is
			# requested to multiply two random numbers
			payload_words.append(self.SERVER_REQUEST_MULTIPLY)
			
			payload_words.append(self.get_random_int(1, 99)) # Integer
			payload_words.append(self.get_random_int(99, 99999) / 999) # Float
			
			self.encode_payload_words(payload_words)
			
			# Immediately send PACKET_TYPE_DATA to all clients with an established session
			amount_of_connected_clients = self.send_data_to_established_clients(payload_words)
			
			if amount_of_connected_clients > 0:
				self.log(self.LOG_NAME_APP, 'Send periodical request to all connected clients.', {
					'Connected': amount_of_connected_clients
				})
				
	def reliable_event_on_packet_received(self, client_id: Optional[int], session_id: int, remote_addr_pair: tuple, packet_type: int, packet_number: int, packet_keyword: int, payload_words: list) -> None:
		super().reliable_event_on_packet_received(client_id, session_id, remote_addr_pair, packet_type, packet_number, packet_keyword, payload_words)
		
		# Do only react to data packets
		if packet_type is not self.PACKET_TYPE_DATA:
			return
			
		# Validate that the packet contains at least one payload word
		if len(payload_words) >= 1:
			# Bytes to string
			self.decode_payload_words(payload_words)
			
			# First word is the request or response id
			request_or_response_id = int(payload_words[0])
			
			# Result from two numbers multiplied
			if request_or_response_id == self.CLIENT_RESPONSE_MULTIPLY:
				result = float(payload_words[1])
				
				self.log(self.LOG_NAME_APP, 'Client <{0}> responded with a result.'.format(self._get_client_id_repr(client_id)), {
					'Result': result
				})
		
		return
	
"""
Server waiting for clients
"""
# WARNING: Do not use the keypairs from the examples. In order to generate the servers
# keypair (public key and secret key), use can use generate_random_server_keypair_hex():
if False:
	(server_public_key_hex, server_secret_key_hex) = Networking().generate_random_server_keypair_hex()

	print('server_public_key_hex', server_public_key_hex)
	print('server_secret_key_hex', server_secret_key_hex)
	
	sys.exit(0)

# Permanent Server Public Key: Shared with the clients.
server_public_key_hex = 'a923e0968a713987d76eba139c434ec3d85d7903f7605b02dcbf09996a6b535d'

# Keep that secret and regenerate a new one for your application. Must not be shared with clients.
server_secret_key_hex = '59a13dd4ed21a0e87432094c3677ae9e34a0f5c1f19686280b54421b603a2bed'

"""
DNS outages can occur even if you use global resolvers. Such an event
can have a drastic impact to your sockets, so it is recommended to create
a fixed record for the hostname (e.g. /etc/hosts on GNU/Linux).
"""

# Create server endpoint
server_endpoint = Networking()
server_endpoint.init(host='0.0.0.0', port=22753, server=True)

server_endpoint.load_keys(server_public_key_hex, server_secret_key_hex, None)

# Run endpoint until program termination
try:
	while True:
		server_endpoint.request_frame()
except KeyboardInterrupt:
	server_endpoint.shutdown()
