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
import os
import sys

DIRNAME = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(1, os.path.abspath(DIRNAME + '/..'))

# Don't create *.pyc files
sys.dont_write_bytecode = True

# Other modules
import time
import secrets

# Monitoring of the traffic
from Monitoring import Monitoring

# Basic Neutrino class
from Neutrino import Neutrino

class Networking(Monitoring, Neutrino):

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
			payload_words[x] = payload_words[x].encode(encoding='utf-8', errors='strict')
			
		return payload_words
		
	"""
	EVENTS
	"""
	def base_server_event_on_session_request(self, client_id: int, session_id: int, client_ip: str, client_port: int) -> bool:
		super().base_server_event_on_session_request(client_id, session_id, client_ip, client_port)
		
		# Randomly refuse connection
		if False:
			if secrets.randbelow(4) == 0:
				print("> Randomly refuse connection for client <{0}:{1}>.".format(client_ip, client_port))
				return False
		
		# Return False to refuse the connection
		return True
		
	def base_server_event_on_shutdown(self) -> None:
		super().base_server_event_on_shutdown()
		
		"""
		DRAINING: Client stops writing, but attempts within a short period of
		time (SESSION_TIMEOUT_ENDING) to read all packets which are remaining.
		"""
		if False:
			# The client will still receive this packet
			self._send_to_authenticated_clients(packet_type=self.PACKET_TYPE_DATA, payload_words=[str.encode('LatePacketForClient1')])
			
			# Depending on SESSION_TIMEOUT_ENDING, the client will also receive this packet
			time.sleep(2.0)
			self._send_to_authenticated_clients(packet_type=self.PACKET_TYPE_DATA, payload_words=[str.encode('LatePacketForClient2')])
			
			# But this packet will be dropped, because it is definitely too late
			time.sleep(0.5)
			self._send_to_authenticated_clients(packet_type=self.PACKET_TYPE_DATA, payload_words=[str.encode('LatePacketForClient3')])
			
	def base_event_on_requested_frame(self, frame_number: int, milliseconds_between_frames: int) -> None:
		super().base_event_on_requested_frame(frame_number, milliseconds_between_frames)

		# The time between frames can be < 1 ms. So we do that only each second.
		if self.each_timeframe(1000):
			payload_words = []
			
			payload_words.append('Current timestamp: {0}.'.format(round(time.time())))
			payload_words.append('An emoji for you: ✈️')
			
			# Immediately send PACKET_TYPE_DATA to all authenticated clients
			server_endpoint.send_data_to_authenticated_clients(self.encode_payload_words(payload_words))
	
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

# Create server endpoint
server_endpoint = Networking()
server_endpoint.init(host='127.0.0.1', port=22753, server=True)

server_endpoint.load_keys(server_public_key_hex, server_secret_key_hex, None)

# Run endpoint until program termination
try:
	while True:
		server_endpoint.request_frame()
except KeyboardInterrupt:
	server_endpoint.shutdown()
