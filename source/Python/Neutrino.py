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

'''
	Code Styling
	  - Type hints for class variables, but none for function variables.
	  - Type hints for function arguments and return values.
	  
	Requirements / Dependencies
	  - Python >= 3.7
	  - PyNaCl (libsodium / https://github.com/jedisct1/libsodium)

	Used Encryption
	  - XChaCha20-Poly1305 (https://libsodium.gitbook.io/doc/secret-key_cryptography/aead/chacha20-poly1305/xchacha20-poly1305_construction)
'''
import sys
import time
import secrets
import struct
import socket
import selectors

import nacl.bindings
import nacl.secret

from typing import Optional

"""
The basic Neutrino class which offers encryption.

Neutrino [> NeutrinoReliable > NeutrinoExtended]
"""
class Neutrino:
	"""
	CONSTANTS: COMMON
	"""
	# Little-endian
	BYTE_ORDER: str = '<'
	
	# Arbitrary but unique 32-bit protocol identifier
	PROTOCOL_IDENTIFIER: int = 0x5baa260c
	
	# Protocol version number which may be iterated only after relevent updates
	PROTOCOL_VERSION: int = 0x02
	
	# Header has a left and right part, because the left part must be left unprotected.
	#
	# LEFT : <[Protocol Identifier = u32 bit (4)] [Protocol Version = u8 bit (1)] [Type = u8 bit (1)] [Session ID = u64 bit (8)]>
	# RIGHT: <[Packet Number = u64 bit (8)]> <[Keyword: Reserved for arbitrary use = u32 bit (4)]>
	HEADER_FORMAT_LEFT: str = 'IBBQ'
	HEADER_FORMAT_RIGHT: str = 'QI'
	
	# Sizes (total header size is 26 bytes)
	HEADER_SIZE_LEFT: int = 4 + 1 + 1 + 8
	HEADER_SIZE_RIGHT: int = 8 + 4
	
	TOTAL_HEADER_SIZE: int = (HEADER_SIZE_LEFT + HEADER_SIZE_RIGHT)
	
	# Maximum amount of words in payload and maximum word size
	#
	# NOTE: This is defined in bytes.
	#
	# For Neutrino Simple this is not really relevant, because it is
	# way more likely to exceed the MAX_PAYLOAD_SIZE.
	MAX_AMOUNT_OF_PAYLOAD_WORDS_IN_BYTES: int = 1 # 1 byte = 2**8-1 = 0–255
	MAX_PAYLOAD_WORD_SIZE_IN_BYTES: int = 2 # 2 bytes = 2**16-1 = 0–65535
	
	MAX_AMOUNT_OF_PAYLOAD_WORDS: int = (2**(8*MAX_AMOUNT_OF_PAYLOAD_WORDS_IN_BYTES) - 1)
	MAX_PAYLOAD_WORD_SIZE: int = (2**(8*MAX_PAYLOAD_WORD_SIZE_IN_BYTES) - 1)
	
	FORMAT_CHAR_MAX_AMOUNT_OF_PAYLOAD_WORDS: str = 'B' # Unsigned char (1 byte)
	FORMAT_CHAR_MAX_PAYLOAD_WORD_SIZE: str = 'H' # Unsigned short (2 bytes)
	
	# All packets, except the PACKET_TYPE_CLIENT_HELLO1, are encrypted
	PACKET_TYPE_CLIENT_HELLO1: int = 0x01
	PACKET_TYPE_SERVER_HELLO2: int = 0x02
	PACKET_TYPE_CLIENT_HELLO3: int = 0x03
	PACKET_TYPE_KEEP_ALIVE: int = 0x04
	PACKET_TYPE_CLOSE: int = 0x05
	PACKET_TYPE_DATA: int = 0x40
	
	PACKET_TYPES: list = [PACKET_TYPE_CLIENT_HELLO1, PACKET_TYPE_SERVER_HELLO2, PACKET_TYPE_CLIENT_HELLO3, PACKET_TYPE_KEEP_ALIVE, PACKET_TYPE_CLOSE, PACKET_TYPE_DATA]
	
	# For best network compatibility, we choose a relatively small
	# UDP packet size; see the QUIC protocol for more information.
	MAX_PACKET_SIZE: int = 1280
	
	# Use that in case you want to force a minimum packet size (realized by padding)
	MIN_PACKET_SIZE: int = 0
	
	# Encryption invokes a small overhead (24 bytes for the nonce, 16 bytes for the encryption header). We need to take care of that once we check the limits.
	PACKET_ENCRYPTION_OVERHEAD: int = (nacl.bindings.crypto_aead.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES + nacl.bindings.crypto_aead.crypto_aead_xchacha20poly1305_ietf_ABYTES)
	
	# Maximum payload size
	MAX_PAYLOAD_SIZE: int = (MAX_PACKET_SIZE - TOTAL_HEADER_SIZE - PACKET_ENCRYPTION_OVERHEAD)
	
	# Padding char
	PACKET_PADDING_CHAR: bytes = b'\x00'
	
	# Max size of sequence number. If you need to change
	# that, you also need to alter HEADER.
	MAX_PACKET_NUMBER_SIZE: int = 2**64-1
	
	INITIAL_PACKET_NUMBER_RANGE_MIN: int = 2**6 # 64
	INITIAL_PACKET_NUMBER_RANGE_MAX: int = 2**31-1	
	
	# Packet numbers
	PACKET_NUMBER_NONE: int = 0x01
	PACKET_NUMBER_PENDING: int = 0x02
	
	# Max keyword size. If you need to change
	# that, you also need to alter HEADER.
	MAX_PACKET_KEYWORD_SIZE: int = 2**32-1	
	
	# We do not use keywords, as this is functionality
	# is reserved for extended classes
	PACKET_KEYWORD_NONE: int = 0x00
	
	# Length of public and secret key in bytes
	PUBLIC_KEY_LENGTH: int = nacl.bindings.crypto_kx.crypto_kx_PUBLIC_KEY_BYTES
	SECRET_KEY_LENGTH: int = nacl.bindings.crypto_kx.crypto_kx_SECRET_KEY_BYTES
	
	"""
	CONSTANTS: CLIENTS
	"""
	# Maximum amount of concurrent connections in total
	MAX_CONNECTIONS_TOTAL: int = 2**16 # 65536
	
	# Maximum amount of concurrent connections for a single client. It does
	# not make any difference, if the session was established or not. Therefore,
	# it is mandatory to remove any information soon if there was no handshake
	# in a very timely manner.
	MAX_CONNECTIONS_CLIENT: int = 32
	
	# Sessions
	MIN_SESSION_ID_SIZE: int = 2**6 # 64
	MAX_SESSION_ID_SIZE: int = 2**64-1
	
	INTERNAL_SESSION_STATE_NONE: int = 0
	INTERNAL_SESSION_STATE_PENDING: int = 1
	INTERNAL_SESSION_STATE_ESTABLISHED: int = 2
	
	CLIENT_SESSION_ID_NONE: int = 0x01
	CLIENT_SESSION_ID_PENDING: int = 0x02	
	
	# Time in milliseconds after a session is destroyed when there are no packets received
	SESSION_TIMEOUT_PENDING: int = 250
	SESSION_TIMEOUT_ESTABLISHED: int = 1500
	
	# Time in milliseconds after a KEEP_ALIVE packet is sent if there is no communication between
	# the endpoints observed. This functionality is mandatory for the loss detection used
	# in NeutrinoExtended, so do not increase this value without a good reason.
	#
	# NOTE: Must be lower than SESSION_TIMEOUT_ESTABLISHED to keep session alive and
	# greater than SESSION_TIMEOUT_PENDING, because KEEP_ALIVE is only allowed for
	# established sessions. I used a third (1/3) of SESSION_TIMEOUT_ESTABLISHED here,
	# while using the half of KEEP_ALIVE_PACKET_TIMEOUT for SESSION_TIMEOUT_PENDING.
	KEEP_ALIVE_PACKET_TIMEOUT: int = 500
	
	# Max client id size
	MAX_LOCAL_CLIENT_ID_SIZE: int = 2**64-1
	
	# Reconnect timeout (milliseconds) after the session expired
	#
	# NOTE: Do not lower this too much, otherwise the server
	# may receive a CLIENT_HELLO and drop it, because the server
	# did not yet remove the client and assumes it is still connected.
	CLIENT_CONNECTION_TIMEOUT_SESSION_EXPIRED: int = 1000
	
	# Reconnect timeout (milliseconds) if the previous reconnect attempt was not successful
	CLIENT_CONNECTION_TIMEOUT_REATTEMPT: int = 3000
	
	# Used for <base_server_event_on_client_unregistered>.
	#
	# CLIENT_UNREGISTER_REASON_VIOLATION:
	#	The client acted unexpectedly by sending malformed packets or specific packet types at the wrong time. This
	#	error is caused due to programming errors. The session is immediately destroyed in that case.
	CLIENT_UNREGISTER_REASON_CLOSE: int = 0x01
	CLIENT_UNREGISTER_REASON_REFUSED: int = 0x02
	CLIENT_UNREGISTER_REASON_TIMEOUT: int = 0x03
	CLIENT_UNREGISTER_REASON_PROTOCOL_VIOLATION: int = 0x04
	
	"""
	CONSTANTS: DEBUG (Used for debugging purposes)
	"""
	PACKET_TYPE_NAMES: dict = {
		PACKET_TYPE_CLIENT_HELLO1: 'CLIENT_HELLO1',
		PACKET_TYPE_SERVER_HELLO2: 'SERVER_HELLO2',
		PACKET_TYPE_CLIENT_HELLO3: 'CLIENT_HELLO3',
		PACKET_TYPE_KEEP_ALIVE: 'KEEP_ALIVE',
		PACKET_TYPE_CLOSE: 'CLOSE',
		PACKET_TYPE_DATA: 'DATA'
	}
	
	CLIENT_UNREGISTER_REASON_NAMES: dict = {
		CLIENT_UNREGISTER_REASON_CLOSE: 'CLOSE',
		CLIENT_UNREGISTER_REASON_REFUSED: 'REFUSED',
		CLIENT_UNREGISTER_REASON_TIMEOUT: 'TIMEOUT',
		CLIENT_UNREGISTER_REASON_PROTOCOL_VIOLATION: 'PROTOCOL_VIOLATION'
	}
	
	"""
	VARIABLES: CRYPTO
	"""
	local_public_key: bytes = None
	local_secret_key: bytes = None
	remote_public_key: bytes = None	
	
	"""
	VARIABLES: ANY ENDPOINT
	"""
	# Host and port of UDP endpoint
	host: str = None
	port: str = None
	
	# Defines if this endpoint is a client or server
	server = False
	
	# Endpoint UDP (datagram) socket
	endpoint = None
	
	# Selector which allows us to read the next packet in the right moment
	selector = None
	
	"""
	VARIABLES: CLIENT SIDE ENDPOINT
	"""
	# Connection session id, packet number, ...
	client_session_id: int = None
	client_packet_number: int = None
	
	# Precalculated session expire time in milliseconds
	client_local_session_expire_time: int = 0
	
	# Time in milliseconds of the very last packet we sent;
	# used to prevent unnecessarily KEEP_ALIVE packets.
	client_last_packet_sent_time: int = 0
	
	# Calculated time (milliseconds) after client tries to reconnect to the server
	client_reattempt_connection_time: int = 0
	
	# Used by the client to interact with encrypted packets
	client_read_key: bytes = None
	client_write_key: bytes = None
	
	"""
	VARIABLES: SERVER SIDE ENDPOINT
	"""
	client_client_ids: dict = {}
	client_session_ids: dict = {}
	client_sessions: dict = {}
	
	"""
	VARIABLES/CONSTANTS: TICKERS
	"""
	SERVERS_TICK_TIME: int = 100 # ms
	CLIENTS_TICK_TIME: int = 25 # ms
	
	last_tick_time: int = 0
	
	"""
	VARIABLES: STATISTICS
	"""
	statistics: dict = { 
		'packets_read_total': 0,
		'packets_sent_total': 0,
		
		'bytes_read_total': 0,
		'bytes_sent_total': 0
	}
	
	"""
	VARIABLES: OTHER
	"""
	frame_number: int = 0

	"""
	INITIALIZATION
	"""
	# Empty to make inheritance easier
	def __init__(self):
		pass
	
	# Initialize endpoint with host and port
	def init(self, host: str, port: int, server: bool=False):
		# Validate some configuration variables
		self.run_checks()
		
		# Configure endpoint
		self.host = host
		self.port = port
		self.server = server
		
		self.endpoint = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		
		if self.is_server() is True:
			self.endpoint.bind((host, port))
		
		# Non-blocking mode
		self.endpoint.setblocking(False)
		
		# Read events
		self.selector = selectors.DefaultSelector()
		self.selector.register(self.endpoint, selectors.EVENT_READ, None)
		
		# Invoke tests
		self.tests()
		
	"""
	TESTS
	"""
	def tests(self) -> None:
		return
		
	"""
	RUN CHECKS
	"""
	def run_checks(self) -> None:
		if self.KEEP_ALIVE_PACKET_TIMEOUT >= self.SESSION_TIMEOUT_ESTABLISHED or self.KEEP_ALIVE_PACKET_TIMEOUT <= self.SESSION_TIMEOUT_PENDING:
			raise Neutrino.ConfigurationError('Value for KEEP_ALIVE_PACKET_TIMEOUT ({0}) must be greater than SESSION_TIMEOUT_ESTABLISHED ({1}) and lower than SESSION_TIMEOUT_PENDING ({2}).'.format(self.KEEP_ALIVE_PACKET_TIMEOUT, self.SESSION_TIMEOUT_ESTABLISHED, self.SESSION_TIMEOUT_PENDING))
	
	"""
	LOOP & TICKERS
	"""
	# Handles all incoming packets forever
	def request_frame(self) -> int:
		self.frame_number += 1
		
		"""
		>>WRITE -> Does happen immediately, see self._write()
		"""
		
		"""
		<<READ
		"""
		for (key, mask) in self.selector.select(timeout=(25 / 1000)):
			"""
			Receive next UDP packet: At this stage, packets are decrypted, but not fully decoded.
			"""
			try:
				try:
					client_id = None
					
					# Packet from any client
					if self.is_server() is True:
						(client_id, session_id, remote_addr_pair, raw_packet, packet_type, packet_number, packet_keyword, payload_words) = self._get_next_packet_from_any_client()
					# Packet from the server
					elif self.is_client() is True:
						(session_id, remote_addr_pair, raw_packet, packet_type, packet_number, packet_keyword, payload_words) = self._get_next_packet_from_the_server()
				
					# Trigger event
					self._register_any_packet(client_id, session_id, remote_addr_pair, raw_packet, packet_type, packet_number, packet_keyword, payload_words)
					
				# Drop unexpected packets
				except Neutrino.NetworkError.UnexpectedPacket as message:
					if self.is_server() is True:
						self._unregister_client(self.CLIENT_UNREGISTER_REASON_PROTOCOL_VIOLATION, client_id)
						
					raise Neutrino.Instruction.DropThisPacket(message)
			
			# Silently drop and trigger event
			except Neutrino.Instruction.DropThisPacket as message:
				self.base_event_on_packet_dropped(message)
		
		"""
		::TICKERS
		"""
		if self.is_server() is True:
			self._servers_tick()
		else:
			self._clients_tick()
			
		# Trigger event
		self.base_event_on_requested_frame(self.frame_number)
		
		return self.frame_number

	# Default: Each 100 ms
	def _servers_tick(self):
		if self.last_tick_time + self.SERVERS_TICK_TIME < self._get_current_time_milliseconds():
			self.last_tick_time = self._get_current_time_milliseconds()
			
			# Remove all timed out client connections
			self._check_for_timed_out_clients()
	
	# Default: Each 25 ms
	def _clients_tick(self):
		if self.last_tick_time + self.CLIENTS_TICK_TIME < self._get_current_time_milliseconds():
			self.last_tick_time = self._get_current_time_milliseconds()
			
			# Invalidate session once expired
			if self.client_local_session_expire_time > 0 and self.client_local_session_expire_time < self._get_current_time_milliseconds():
				self.client_session_id = None
				self.client_packet_number = None
				
				# Session expired
				if self.client_local_session_expire_time > 0:
					# Reset session expire time
					self.client_local_session_expire_time = 0.0
					
					# Set timeout for re-establishing connection to the server
					self.client_reattempt_connection_time = (self._get_current_time_milliseconds() + self.CLIENT_CONNECTION_TIMEOUT_SESSION_EXPIRED)
				# Failed to establish connection at all
				else:
					pass
			
			# Establish encrypted session to the server
			if self.connected_to_server() is False:
				if self.client_reattempt_connection_time < self._get_current_time_milliseconds():
					self.connect_to_server()
					
					# Set timeout for next retry
					self.client_reattempt_connection_time = (self._get_current_time_milliseconds() + self.CLIENT_CONNECTION_TIMEOUT_REATTEMPT)
			else:
				# Periodically send KEEP_ALIVE packets to keep alive the session
				if self.client_last_packet_sent_time + (self.KEEP_ALIVE_PACKET_TIMEOUT - self.CLIENTS_TICK_TIME) < self._get_current_time_milliseconds():
					self._send_keep_alive_packet(None, None)
	
	"""
	CRYPTO KEYS
	"""	
	# Loads local and remote keys
	def load_keys(self, local_public_key_hex: str, local_secret_key_hex: str, remote_public_key_hex: str=None) -> None:
		self._load_local_keypair(local_public_key_hex, local_secret_key_hex)

		if self.is_client() is True:
			self._load_remote_public_key(remote_public_key_hex)
			self._reload_local_crypto_keys()
	
	# Loads the endpoints keypair, where the keys must be applied in hex
	def _load_local_keypair(self, local_public_key_hex: str=None, local_secret_key_hex: str=None) -> None:
		# Auto-generate for clients, because they usually use a new keypair for each connection
		if self.is_client() is True:
			if local_public_key_hex is None and local_secret_key_hex is None:
				(local_public_key_hex, local_secret_key_hex) = self._generate_keypair_hex()

		# Set from hex
		try:
			self.local_public_key = bytes.fromhex(local_public_key_hex)
			self.local_secret_key = bytes.fromhex(local_secret_key_hex)
		except ValueError as message:
			raise Neutrino.LocalCryptoError.InvalidPublicOrSecretKey(message) from None
		
		# Validate length
		if len(self.local_public_key) is not self.PUBLIC_KEY_LENGTH or len(self.local_secret_key) is not self.SECRET_KEY_LENGTH:
			raise Neutrino.LocalCryptoError.InvalidPublicOrSecretKey('Length of public/secret key is expected to be exactly {0}/{1} bytes.'.format(self.PUBLIC_KEY_LENGTH, self.SECRET_KEY_LENGTH))
	
	# Loads the public key of the remote endpoint (usually the servers one)
	def _load_remote_public_key(self, remote_public_key_hex: str=None) -> None:	
		# Clients need to load the public key of the server
		try:
			self.remote_public_key = bytes.fromhex(remote_public_key_hex)
		except ValueError as message:
			raise Neutrino.LocalCryptoError.InvalidPublicOrSecretKey(message) from None
		
		if len(self.remote_public_key) is not self.PUBLIC_KEY_LENGTH:
			raise Neutrino.LocalCryptoError.InvalidPublicOrSecretKey('Length of public/secret key is expected to be exactly {0}/{1} bytes.'.format(self.PUBLIC_KEY_LENGTH, self.SECRET_KEY_LENGTH))
	
	# Used by the client to automatically reload the client's public and secret keys,
	# initially and, after that, for each further connection attempt.
	def _reload_local_crypto_keys(self) -> None:
		self._load_local_keypair(None, None)
		
		# Derive read/write encryption keys (secrets)
		(self.client_read_key, self.client_write_key) = self._derive_client_encryption_keys_from_keypair(self.local_public_key, self.local_secret_key, self.remote_public_key)
	
	# Return local public key
	def get_local_public_key(self):
		return self.local_public_key
	
	"""
	CRYPTO: ALIAS FUNCTIONS

	> The XChaCha20-Poly1305 construction can safely encrypt a practically unlimited number of messages
	> with the same key, without any practical limit to the size of a message (up to ~ 2^64 bytes).
	>
	> As an alternative to counters, its large nonce size (192-bit) allows random nonces to be safely used.

	https://libsodium.gitbook.io/doc/secret-key_cryptography/aead/chacha20-poly1305/xchacha20-poly1305_construction
	"""
	# Encrypt given plaintext by secret key
	def _encrypt_plaintext_by_key(self, raw_key: bytes, plaintext: bytes, associated_data: bytes=b'') -> bytes:
		# Generate a large 192-bit (24 bytes) nonce
		random_nonce = self._get_random_bytes(nacl.bindings.crypto_aead.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES)
		
		# Encrypt and return concatenation(nonce + ciphertext)
		ciphertext = nacl.bindings.crypto_aead_xchacha20poly1305_ietf_encrypt(message=plaintext, aad=associated_data, nonce=random_nonce, key=raw_key)
		
		return random_nonce + ciphertext
		
	# Decrypt given ciphertext by secret key
	def _decrypt_ciphertext_by_key(self, raw_key: bytes, ciphertext: bytes, associated_data: bytes=b'') -> bytes:
		# From ciphertext separate nonce and encrypted plaintext
		(provided_nonce, encrypted_plaintext) = (ciphertext[0:nacl.bindings.crypto_aead.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES], ciphertext[nacl.bindings.crypto_aead.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES:])
		
		try:
			return nacl.bindings.crypto_aead_xchacha20poly1305_ietf_decrypt(ciphertext=encrypted_plaintext, aad=associated_data, nonce=provided_nonce, key=raw_key)
		except nacl.exceptions.CryptoError:
			raise Neutrino.LocalCryptoError.DecryptionFailed
			
	# Alias for libsodium::crypto_kx_keypair()
	def _generate_keypair(self) -> tuple:
		return nacl.bindings.crypto_kx_keypair()
	
	# Same as _generate_keypair(), but keys in HEX and not in BYTES
	def _generate_keypair_hex(self) -> tuple:
		(public, secret) = self._generate_keypair()
		
		return (public.hex(), secret.hex())
		
	# Alias for libsodium::crypto_kx_client_session_keys()
	def _derive_client_encryption_keys_from_keypair(self, client_public_key: bytes, client_secret_key: bytes, server_public_key: bytes) -> tuple:
		return nacl.bindings.crypto_kx_client_session_keys(client_public_key, client_secret_key, server_public_key)
	
	# Alias for libsodium::crypto_kx_server_session_keys()
	def _derive_server_encryption_keys_from_keypair(self, server_public_key: bytes, server_secret_key: bytes, client_public_key: bytes) -> tuple:
		return nacl.bindings.crypto_kx_server_session_keys(server_public_key, server_secret_key, client_public_key)
	
	"""
	PACKET NUMBERS
	"""
	# Generate packet number with random integer between 2^a and 2^b-1
	# See: https://tools.ietf.org/id/draft-ietf-quic-transport-06.html#initial-packet-number
	def _generate_initial_random_packet_number(self):
		return self._get_random_int(self.INITIAL_PACKET_NUMBER_RANGE_MIN, self.INITIAL_PACKET_NUMBER_RANGE_MAX)
	
	"""
	ENCODING / DECODING
	
	Payload starts with amount of words (u8 bit), following with n words starting with
	the word length. Using delimiters would not be safe.
		
		<[Number of Words = u8 bit (1)] [n * [Word Length = u16 bit (2)] [Word = ? bit]]>
	
	"""
	def _pack(self, format: str, *args) -> bytes:
		return struct.pack(self.BYTE_ORDER + format, *args)
			
	def _unpack(self, format: str, *args) -> tuple:
		return struct.unpack(self.BYTE_ORDER + format, *args)
	
	# Integers to/from bytes
	def _int32_to_bytes(self, number) -> bytes:
		return struct.pack(self.BYTE_ORDER + 'I', number)
		
	def _int32_from_bytes(self, number) -> int:
		return struct.unpack(self.BYTE_ORDER + 'I', number)[0]
		
	def _int64_to_bytes(self, number) -> bytes:
		return struct.pack(self.BYTE_ORDER + 'Q', number)
		
	def _int64_from_bytes(self, number) -> int:
		return struct.unpack(self.BYTE_ORDER + 'Q', number)[0]
		
	# Convert words into payload
	def _byte_words_to_payload(self, payload_words: list=[]) -> bytes:
		if type(payload_words) is not list:
			raise Neutrino.EncodingError("'payload_words' must be a list, containing items of type 'bytes'.")
		
		# Maximum amount of words must not be exceeded
		amount_of_byte_words = len(payload_words)
		
		if amount_of_byte_words > self.MAX_AMOUNT_OF_PAYLOAD_WORDS:
			raise Neutrino.EncodingError('Payload must not contain more than {0} words (got {1}).'.format(self.MAX_AMOUNT_OF_PAYLOAD_WORDS, amount_of_byte_words))
		
		# Start with the number of words
		raw_payload_bytes = self._pack(self.FORMAT_CHAR_MAX_AMOUNT_OF_PAYLOAD_WORDS, amount_of_byte_words)
		
		for byte_word in payload_words:
			if type(byte_word) is not bytes:
				raise Neutrino.EncodingError("Item in list 'payload_words' must be of type 'bytes': {0}".format(byte_word))
			
			# Maximum word length must not be exceeded
			word_size = len(byte_word)
			
			if word_size > self.MAX_PAYLOAD_WORD_SIZE:
				raise Neutrino.EncodingError('Size of this word ({0} bytes) would exceed maximum word size of {1} bytes.'.format(word_size, self.MAX_PAYLOAD_WORD_SIZE))
				
			raw_payload_bytes += self._pack(self.FORMAT_CHAR_MAX_PAYLOAD_WORD_SIZE, word_size)
			raw_payload_bytes += byte_word
			
		return raw_payload_bytes
		
	# Encrypt encoded packet (= encode and then encrypt)
	def _encrypt_encoded_packet(self, raw_key: bytes, raw_packet: bytes) -> bytes:
		# Header is partially encrypted and payload is fully encrypted
		(left_unprotected, right_encrypted) = (raw_packet[0:self.HEADER_SIZE_LEFT], raw_packet[self.HEADER_SIZE_LEFT:])
		
		# Encrypt right part
		right_encrypted = self._encrypt_plaintext_by_key(raw_key=raw_key, plaintext=right_encrypted)
		
		# Concatenate unprotected and encrypted parts
		raw_packet_encrypted = left_unprotected + right_encrypted
		
		return raw_packet_encrypted
	
	# Encode packet from raw bytes words (this does not take care of UTF-8 encodes strings)
	def _encode_packet(self, packet_type: int, packet_number: int, packet_keyword: int, session_id: int, raw_payload_bytes: bytes=None, payload_words: list=[], padding: int=0) -> bytes:
		if type(packet_type) is not int:
			raise Neutrino.EncodingError("'packet_type' must be type of 'int', but given: {0}".format(packet_type))
			
		if type(packet_number) is not int:
			raise Neutrino.EncodingError("'packet_number' must be type of 'int', but given: {0}".format(packet_number))
			
		if type(packet_keyword) is not int:
			raise Neutrino.EncodingError("'packet_keyword' must be type of 'int', but given: {0}".format(packet_keyword))
			
		if type(session_id) is not int:
			raise Neutrino.EncodingError("'session_id' must be type of 'int', but given: {0}".format(session_id))
			
		# Convert byte words list into payload
		if raw_payload_bytes is None:
			raw_payload_bytes = self._byte_words_to_payload(payload_words)
		
		# Ensure that max payload size (and thus max packet size) is not exceeded
		payload_size = len(raw_payload_bytes)
		
		if payload_size > self.MAX_PAYLOAD_SIZE:
			raise Neutrino.EncodingError('Payload size of this packet ({0} bytes) would exceed maximum size of {1} bytes.'.format(payload_size, self.MAX_PAYLOAD_SIZE))
			
		# Create header
		raw_packet = b''
		raw_packet += self._pack(self.HEADER_FORMAT_LEFT, self.PROTOCOL_IDENTIFIER, self.PROTOCOL_VERSION, packet_type, session_id)
		raw_packet += self._pack(self.HEADER_FORMAT_RIGHT, packet_number, packet_keyword)
		
		# Just append bytes payload to the header instead of packing it
		raw_packet += raw_payload_bytes
		
		# Pad out packet until max size (padding) is reached
		if padding is 0:
			padding = self.MIN_PACKET_SIZE
			
		if padding > len(raw_packet):
			raw_packet += (padding - len(raw_packet)) * self.PACKET_PADDING_CHAR
		
		return raw_packet
		
	# Decrypt encoded packet (= decrypt ant then decode)
	def _decrypt_encoded_packet(self, raw_key: bytes, raw_packet: bytes) -> bytes:
		# Header is partially encrypted and payload is fully encrypted
		(left_unprotected, right_decrypted) = (raw_packet[0:self.HEADER_SIZE_LEFT], raw_packet[self.HEADER_SIZE_LEFT:])
		
		# Decrypt right part
		right_decrypted = self._decrypt_ciphertext_by_key(raw_key=raw_key, ciphertext=right_decrypted)
		
		# Concatenate unprotected and decrypted parts
		raw_packet_decrypted = left_unprotected + right_decrypted
		
		return raw_packet_decrypted
	
	# Decode the unprotected left part of the packet header
	def _decode_and_validate_unprotected_packet_header(self, raw_packet: bytes) -> tuple:
		# Calculate total packet size
		packet_size = len(raw_packet)

		# Invalid header size
		if packet_size < self.TOTAL_HEADER_SIZE:
			raise Neutrino.NetworkError.InvalidPacket('Wrong header size (expected {0}, but got {1}).'.format(self.TOTAL_HEADER_SIZE, packet_size))	
	
		try:
			(protocol_identifier, protocol_version, packet_type, session_id) = self._unpack(self.HEADER_FORMAT_LEFT, raw_packet[0:self.HEADER_SIZE_LEFT])
		except struct.error as message:
			raise Neutrino.NetworkError.InvalidPacket(('Malformed header (unprotected part).', message)) from None
		
		# Validate header information
		if protocol_identifier != self.PROTOCOL_IDENTIFIER:
			raise Neutrino.NetworkError.InvalidPacket('Unexpected protocol identifier.')
			
		if protocol_version not in [self.PROTOCOL_VERSION]:
			raise Neutrino.NetworkError.InvalidPacket('Incompatible protocol version.')
			
		if packet_type not in self.PACKET_TYPES:
			raise Neutrino.NetworkError.InvalidPacket('Invalid packet type.')
			
		if not self._is_valid_client_session_id(session_id):
			raise Neutrino.NetworkError.InvalidPacket('Invalid session id.')
			
		return (packet_type, session_id)
	
	# Combined call of self._decode_and_validate_decrypted_packet_[header|payload]()
	def _decode_and_validate_decrypted_packet_header_and_payload(self, raw_packet: bytes) -> tuple:
		# Packet number and keyword
		(packet_number, packet_keyword) = self._decode_and_validate_decrypted_packet_header(raw_packet)
		
		# Payload
		payload_words = self._decode_and_validate_decrypted_packet_payload(raw_packet)
		
		return (packet_number, packet_keyword, payload_words)
	
	# Decode the (usually previously) decrypted right part of the packet header
	def _decode_and_validate_decrypted_packet_header(self, raw_packet: bytes) -> tuple:
		try:
			(packet_number, packet_keyword) = self._unpack(self.HEADER_FORMAT_RIGHT, raw_packet[self.HEADER_SIZE_LEFT:(self.HEADER_SIZE_LEFT + self.HEADER_SIZE_RIGHT)])
		except struct.error as message:
			raise Neutrino.NetworkError.InvalidPacket(('Malformed header (decrypted part).', message)) from None
			
		return (packet_number, packet_keyword)
		
	# Decode the (usually previously) decrypted payload of the packet
	def _decode_and_validate_decrypted_packet_payload(self, raw_packet: bytes) -> tuple:
		# Payload is the rest of the packet
		payload_bytes = raw_packet[self.TOTAL_HEADER_SIZE:]	
		
		# No payload
		payload_bytes_size = len(payload_bytes)
		
		if payload_bytes_size == 0:
			raise Neutrino.NetworkError.InvalidPacket('Empty payload received.')
		
		# Get and validate amount of payload words 
		(amount_of_byte_words,) = self._unpack(self.FORMAT_CHAR_MAX_AMOUNT_OF_PAYLOAD_WORDS, payload_bytes[0:self.MAX_AMOUNT_OF_PAYLOAD_WORDS_IN_BYTES])
		
		if amount_of_byte_words < 0:
			raise Neutrino.NetworkError.InvalidPacket("Malformed payload: 'amount_of_byte_words' rendered to an invalid value. Got {0}, but expected a value between 0 and {1}.".format(amount_of_byte_words, self.MAX_AMOUNT_OF_PAYLOAD_WORDS))
		
		# Place offset after the number of words byte(s)
		offset = self.MAX_AMOUNT_OF_PAYLOAD_WORDS_IN_BYTES
		
		# Extract all byte words
		payload_words = []
		
		for x in range(0, amount_of_byte_words):
			try:
				# Word size
				(byte_word_length,) = self._unpack(self.FORMAT_CHAR_MAX_PAYLOAD_WORD_SIZE, payload_bytes[offset:(offset + self.MAX_PAYLOAD_WORD_SIZE_IN_BYTES)])
				offset += self.MAX_PAYLOAD_WORD_SIZE_IN_BYTES
				
				if byte_word_length <= 0:
					raise Neutrino.NetworkError.InvalidPacket("Malformed payload: 'byte_word_length' rendered to an invalid value. Got {0}, but expected a value between 1 and {1}.".format(amount_of_byte_words, self.MAX_PAYLOAD_WORD_SIZE))
				
				# Byte word ([Word = ? bytes])
				payload_words.append(payload_bytes[offset:(offset + byte_word_length)])
				offset += byte_word_length
			except struct.error as e:
				raise Neutrino.NetworkError.InvalidPacket("Malformed payload: Cannot unpack word <{0}/{1}>, expected range {2}–{3}, total packet size: {4} bytes.".format(x, amount_of_byte_words, offset, (offset + byte_word_length), payload_bytes_size), e) from None
		
		"""
		# The right side of the payload needs to be either empty *or* only consist of PACKET_PADDING_CHAR bytes,
		# which, after stripping, also results the right side to be empty.
		if len(payload_bytes[offset:].rstrip(self.PACKET_PADDING_CHAR)) != 0:
			raise Neutrino.NetworkError.InvalidPacket('Unexpected payload size of {0} bytes.'.format(offset))
		"""
		unpadded_payload_bytes_size = len(payload_bytes.rstrip(self.PACKET_PADDING_CHAR))
		
		if offset < unpadded_payload_bytes_size:
			raise Neutrino.NetworkError.InvalidPacket('Could not extract all words from payload. Payload may contain unexpected bytes (expected {0} bytes, but received {1}).'.format(offset, unpadded_payload_bytes_size))
		
		return payload_words
	
	"""
	NETWORK: READ
	"""
	def _read(self) -> tuple:
		# All or nothing: Receive n bytes of the next UDP
		# packet and discard any remaining bytes.
		# 
		# (However, at this point, we would always fetch the
		# maximum for a UDP packet which is 64 KiB).
		#
		# Throws BlockingIOError in non-blocking mode, if
		# there are no packets left to read. Not relevant here,
		# because we use Pythons DefaultSelector().
		(raw_packet, remote_addr_pair) = self.endpoint.recvfrom(2**16)
		
		raw_packet_size = len(raw_packet)
		
		if raw_packet_size > self.MAX_PACKET_SIZE:
			raise Neutrino.NetworkError.InvalidPacket('Size of this packet ({0} bytes) exceeds maximum size of {1} bytes.'.format(raw_packet_size, self.MAX_PACKET_SIZE))
		
		# Decode and validate only unprotected header parts and validate total header size
		(packet_type, session_id) = self._decode_and_validate_unprotected_packet_header(raw_packet)
		
		# Statistics
		self.statistics['packets_read_total'] += 1
		self.statistics['bytes_read_total'] += raw_packet_size
		
		return (remote_addr_pair, raw_packet, packet_type, session_id)
	
	# Servers read function
	# 	request_frame() >> _get_next_packet_from_any_client() >> _servers_read()
	def _servers_read(self) -> tuple:
		((client_ip, client_port), raw_packet, packet_type, session_id) = self._read()
		
		# Only, if session id must be given
		if self._is_not_pending_client_session_id(session_id):
			# Try to get client id by session id
			client_id = self._get_client_id_by_session_id(session_id)
	
			# Find out the secret encryption (write) key
			raw_key = self._get_client_session_read_key_by_client_id(client_id)
		
			# Encrypted encoded packet => Decrypted encoded packet
			try:
				raw_packet = self._decrypt_encoded_packet(raw_key=raw_key, raw_packet=raw_packet)
			except Neutrino.LocalCryptoError.DecryptionFailed:
				raise Neutrino.LocalCryptoError.DecryptionFailed('Failed to decrypt packet of client <client_id:session_id> <{0:1}.'.format(self._get_default_int_repr(client_id), self._get_default_int_repr(session_id)))
				
			# Update current host and port of the client
			self._update_client_addr(client_id, client_ip, client_port)
		
		# Decode and validate the part of the decrypted protected header, then, decode and validate payload
		(packet_number, packet_keyword, payload_words) = self._decode_and_validate_decrypted_packet_header_and_payload(raw_packet)
		
		# Get existing client
		try:
			client_id = self._get_client_id_by_addr(client_ip, client_port)
		# Add client
		except Neutrino.ClientError.NotFoundError:
			client_id = self._register_client(client_ip, client_port)
		
		# Trigger event
		self.base_event_on_packet_received(client_id, session_id, (client_ip, client_port), raw_packet, packet_type, packet_number, packet_keyword, payload_words)		
		
		return (client_id, session_id, (client_ip, client_port), raw_packet, packet_type, packet_number, packet_keyword, payload_words)
		
	# Clients read function
	# 	request_frame() >> _get_next_packet_from_the_server() >> _clients_read()
	def _clients_read(self) -> tuple:
		(remote_addr_pair, raw_packet, packet_type, session_id) = self._read()
		
		# Only, if session id must be given
		if self._is_not_pending_client_session_id(session_id):
			# Encrypted encoded packet => Decrypted encoded packet
			raw_packet = self._decrypt_encoded_packet(raw_key=self.client_read_key, raw_packet=raw_packet)
		
		# Decode and validate the part of the decrypted protected header, then, decode and validate payload
		(packet_number, packet_keyword, payload_words) = self._decode_and_validate_decrypted_packet_header_and_payload(raw_packet)
		
		# Trigger event
		self.base_event_on_packet_received(None, session_id, remote_addr_pair, raw_packet, packet_type, packet_number, packet_keyword, payload_words)	
		
		return (session_id, remote_addr_pair, raw_packet, packet_type, packet_number, packet_keyword, payload_words)
		
	# Receives the next packet from any client
	def _get_next_packet_from_any_client(self) -> tuple:
		try:
			return self._servers_read()
		except (Neutrino.ClientError.NotFoundError, Neutrino.ClientError.SessionError, Neutrino.RemoteCryptoError, Neutrino.NetworkError.InvalidPacket) as message:
			raise Neutrino.Instruction.DropThisPacket(message)
			
	# Receives the next packet from the server
	def _get_next_packet_from_the_server(self) -> tuple:
		try:
			return self._clients_read()
		except (Neutrino.RemoteCryptoError, Neutrino.NetworkError.InvalidPacket) as message:
			raise Neutrino.Instruction.DropThisPacket(message)
	
	"""
	NETWORK: WRITE
	"""
	# Immediately send to endpoint
	def _write(self, remote_addr_pair: tuple, raw_packet: bytes) -> int:
		# Immediately send out packet
		bytes_sent = self.endpoint.sendto(raw_packet, remote_addr_pair)
		
		# Statistics
		self.statistics['packets_sent_total'] += 1
		self.statistics['bytes_sent_total'] += bytes_sent
		
		# Sent time of the very last packet
		if self.is_client() is True:
			self.client_last_packet_sent_time = self._get_current_time_milliseconds()
		
		return bytes_sent
	
	# Send packet to any endpoint
	def _send_packet(self, client_id: Optional[int], session_id: int, remote_addr_pair: Optional[tuple], packet_type: int, packet_number: int, packet_keyword: int, raw_payload_bytes: bytes=None, payload_words: list=[], padding: int=0) -> tuple:
		# Ensure client_id is given if endpoint is the server
		if self.is_server() is True and client_id is None:
			raise Neutrino.LogicError("'client_id' cannot be None if packet is sent to a client.")
			
		# Get ip and port of client
		if client_id is not None:
			remote_addr_pair = self._get_client_addr_by_client_id(client_id)
			
		# Create encoded packet
		raw_packet = self._encode_packet(packet_type, packet_number, packet_keyword, session_id, raw_payload_bytes, payload_words, padding)
		
		# As long it is not the initial client's HELLO packet
		if packet_type not in [self.PACKET_TYPE_CLIENT_HELLO1]:
			# Cannot encrypt packets if no valid session id is given
			if session_id is self.CLIENT_SESSION_ID_PENDING:
				raise Neutrino.LogicError("Cannot encrypt packet if no valid session id is given.")
		
			# Find out the secret encryption (write) key
			raw_key = b''
			
			if self.is_client() is True:
				raw_key = self.client_write_key
			else:
				raw_key = self._get_client_session_write_key_by_client_id(client_id)
				
			# Encrypt
			raw_packet = self._encrypt_encoded_packet(raw_key=raw_key, raw_packet=raw_packet)
		
		# Immediately send out to endpoint
		self._write(remote_addr_pair, raw_packet)
	
		# Trigger event
		self.base_event_on_packet_sent(client_id, session_id, remote_addr_pair, raw_packet, packet_type, packet_number, packet_keyword, payload_words)
		
		return (raw_packet, packet_number)
		
	# Send packet to a client
	def _send_to_client(self, client_id: int, packet_type: int, session_id: int, payload_words: list=[], padding: int=0) -> tuple:
		# Get current clients session packet number and increment it afterwards
		packet_number = self._get_servers_client_session_packet_number(client_id=client_id, increment=True)
		
		# Send packet to client
		return self._send_packet(client_id, session_id, None, packet_type, packet_number, self.PACKET_KEYWORD_NONE, None, payload_words, padding)

	# Send packet to the server
	def _send_to_server(self, packet_type: int, session_id: int, payload_words: list=[], padding: int=0) -> tuple:
		packet_number = self.PACKET_NUMBER_PENDING
		
		# As long it is not the initial client's HELLO packet
		if packet_type not in [self.PACKET_TYPE_CLIENT_HELLO1]:
			# Get current clients packet number and increment it afterwards
			packet_number = self._get_clients_packet_number(increment=True)
		
		# Send packet to server
		return self._send_packet(None, session_id, (self.host, self.port), packet_type, packet_number, self.PACKET_KEYWORD_NONE, None, payload_words, padding)

	"""
	CLIENTS
	"""
	# Prepare connection to the server
	def connect_to_server(self):
		# Generate new client keypair for each connection attempt
		self._reload_local_crypto_keys()
	
		# Send unprotected HELLO packet to server to prepare the encrypted connection.
		# The initial HELLO packet must be padded out to prevent amplification attacks.
		self._send_to_server(packet_type=self.PACKET_TYPE_CLIENT_HELLO1, session_id=self.CLIENT_SESSION_ID_PENDING, payload_words=[self.get_local_public_key()], padding=self.MAX_PACKET_SIZE)
		
		# Trigger event
		self.base_client_event_on_request_session()
		
	# Close connection to the server
	def close_connection_to_server(self):
		if self.client_session_id is None:
			raise Neutrino.NetworkError.NotConnected('Client is not connected to server.')
			
		self._send_to_server(packet_type=self.PACKET_TYPE_CLOSE, session_id=self.client_session_id)
	
	# Pass through all clients and delete all information about clients which timed out
	def _check_for_timed_out_clients(self):
		pass
		#for client_id in list(self.client_sessions):
			# Session is expired
			#if self.client_sessions[client_id]['local_session_expire_time'] < self._get_current_time_milliseconds():
			#	(client_ip, client_port, session_id) = self._unregister_client(self.CLIENT_UNREGISTER_REASON_TIMEOUT, client_id)
	
	# Adds a new client
	def _register_client(self, client_ip: str, client_port: int) -> int:
		client_id = self._add_client_id_by_addr(client_ip, client_port)
		
		self.client_sessions[client_id] = {
			# Remote addr
			'ip': client_ip,
			'port': client_port,
			
			# Session
			'session_id': None,
			'session_state': self.INTERNAL_SESSION_STATE_NONE,
			'local_session_expire_time': (self._get_current_time_milliseconds() + self.SESSION_TIMEOUT_PENDING),
			
			# Cryptographic read and write keys derived from the clients
			# public key. These keys change for every connection.
			'read_key': b'',
			'write_key': b'',
			
			# Current packet number
			'packet_number': None
		}
		
		return client_id
	
	# Destroys client session and removes any other information
	def _unregister_client(self, reason: int, client_id: int) -> tuple:
		# Get client information
		(client_ip, client_port, session_id) = (self.client_sessions[client_id]['ip'], self.client_sessions[client_id]['port'], self.client_sessions[client_id]['session_id'])
		
		# Delete all client information
		del self.client_sessions[client_id]
		
		if session_id is not None:
			del self.client_session_ids[session_id]
		
		del self.client_client_ids[client_ip][client_port]
		
		if len(self.client_client_ids[client_ip]) == 0:
			del self.client_client_ids[client_ip]
		
		# Trigger event
		self.base_server_event_on_client_unregistered(reason, client_id, session_id, client_ip, client_port)
		
		return (client_ip, client_port, session_id)
	
	# Get client id by given addr pair: (ip, port)
	def _get_client_id_by_addr(self, client_ip: str, client_port: int) -> int:
		try:
			return self.client_client_ids[client_ip][client_port]
		except KeyError:
			raise Neutrino.ClientError.NotFoundError('No client identified by <ip:port> (<{0}:{1}>) found.'.format(client_ip, client_port)) from None
	
	# Get client addr by given client id
	def _get_client_addr_by_client_id(self, client_id: int) -> tuple:
		try:
			return (self.client_sessions[client_id]['ip'], self.client_sessions[client_id]['port'])
		except KeyError:
			raise Neutrino.ClientError.NotFoundError('No client session identified by <client_id> (<{0}>) found.'.format(self._get_default_int_repr(client_id))) from None
	
	# Get client id by session id
	def _get_client_id_by_session_id(self, session_id: int) -> int:
		try:
			return self.client_session_ids[session_id]
		except KeyError:
			raise Neutrino.ClientError.NotFoundError('No client identified by <session_id> (<{0}>) found.'.format(self._get_default_int_repr(session_id))) from None	
	
	# Get client's session secret encryption read/write key by client id
	def _get_client_session_read_key_by_client_id(self, client_id: int) -> bytes:
		try:
			return self.client_sessions[client_id]['read_key']
		except KeyError:
			raise Neutrino.ClientError.NotFoundError('No client session identified by <client_id> (<{0}>) found.'.format(self._get_default_int_repr(client_id))) from None
	
	def _get_client_session_write_key_by_client_id(self, client_id: int) -> bytes:
		try:
			return self.client_sessions[client_id]['write_key']
		except KeyError:
			raise Neutrino.ClientError.NotFoundError('No client session identified by <client_id> (<{0}>) found.'.format(self._get_default_int_repr(client_id))) from None
	
	# Add new client id using the given addr pair
	def _add_client_id_by_addr(self, client_ip: str, client_port: int) -> int:
		# Limit of total connections
		if (len(self.client_client_ids) + 1) > self.MAX_CONNECTIONS_TOTAL:
			raise Neutrino.LimitExceededError('Adding new client would exceed total connections limit of {0}.'.format(self.MAX_CONNECTIONS_TOTAL))
		
		if client_ip in self.client_client_ids:
			# Limit of connections per client
			if (len(self.client_client_ids[client_ip]) + 1) > self.MAX_CONNECTIONS_CLIENT:
				raise Neutrino.LimitExceededError('Adding new client would exceed connections per client limit of {0}.'.format(self.MAX_CONNECTIONS_CLIENT))
		else:
			self.client_client_ids[client_ip] = {}
		
		# Cannot have two connections from the same client at the same port.
		# NOTE: This may happen if _get_client_id_by_addr() was not called before.
		if client_port in self.client_client_ids[client_ip]:
			raise Neutrino.LogicError('Cannot initialize a client twice with the same <ip:port> pair.')
		else:
			self.client_client_ids[client_ip][client_port] = self._generate_random_local_client_id()

		return self.client_client_ids[client_ip][client_port]
	
	# Update current client addr pair
	def _update_client_addr(self, client_id: int, new_client_ip: str, new_client_port: int) -> None:
		old_client_ip = self.client_sessions[client_id]['ip']
		old_client_port = self.client_sessions[client_id]['port']
		
		# Did the addr pair change at all?
		if old_client_ip != new_client_ip or old_client_port != new_client_port:
			# Delete old client information
			del self.client_client_ids[old_client_ip][old_client_port]
			
			if len(self.client_client_ids[old_client_ip]) == 0:
				del self.client_client_ids[old_client_ip]		
			
			# Update to new client information
			self.client_sessions[client_id]['ip'] = new_client_ip
			self.client_sessions[client_id]['port'] = new_client_port
			
			if new_client_ip not in self.client_client_ids:
				self.client_client_ids[new_client_ip] = {}
			
			self.client_client_ids[new_client_ip][new_client_port] = client_id
			
			# Trigger event
			self.base_server_event_on_client_addr_change(client_id, old_client_ip, old_client_port, new_client_ip, new_client_port)
	
	# Get (and possibly increment) the servers packet number for a specific client session
	def _get_servers_client_session_packet_number(self, client_id: int, increment: bool=False):
		packet_number = self.client_sessions[client_id]['packet_number']
		
		if increment is True:
			self.client_sessions[client_id]['packet_number'] += 1
			
		return packet_number
	
	# Get (and possibly increment) the clients sending packet number
	def _get_clients_packet_number(self, increment: bool=False):
		# Generate initial random packet number which is used
		# for packets sent to the server
		if self.client_packet_number is None:
			self.client_packet_number = self._generate_initial_random_packet_number()
			
		packet_number = self.client_packet_number
		
		if increment is True:
			self.client_packet_number += 1
			
		return packet_number
		
	# Generate random client id for local use (64 bit)
	def _generate_random_local_client_id(self) -> int:
		random_client_id = self._get_random_int(0, self.MAX_LOCAL_CLIENT_ID_SIZE)
		
		# This is indeed very unlikely, but just to be sure
		while random_client_id in self.client_sessions:
			return self._generate_random_local_client_id()
			
		return random_client_id
		
	# Generate random session id (64 bit)
	def _generate_random_client_session_id(self) -> int:
		random_session_id = self._get_random_int(self.MIN_SESSION_ID_SIZE, self.MAX_SESSION_ID_SIZE)
		
		# This is indeed very unlikely, but just to be sure
		while random_session_id in self.client_session_ids:
			return self._generate_random_client_session_id()
			
		return random_session_id
	
	# Validate session id
	def _is_valid_client_session_id(self, session_id: int) -> bool:
		if session_id in [self.CLIENT_SESSION_ID_PENDING]:
			return True
			
		if session_id < self.MIN_SESSION_ID_SIZE or session_id > self.MAX_SESSION_ID_SIZE:
			return False
			
		return True
	
	# Same as _is_valid_client_session_id(), but fail for pending sessions
	def _is_not_pending_client_session_id(self, session_id: int) -> bool:
		if self._is_valid_client_session_id(session_id):
			if session_id in [self.CLIENT_SESSION_ID_PENDING]:
				return False
				
			return True
			
		return False
	
	# Get this client endpoints session id
	def get_this_client_session_id(self):
		return self.client_session_id
	
	# Check if client endpoint is connected to the server
	def connected_to_server(self):
		if self.client_session_id is not None:
			return True
	
		return False
		
	# Register packet from the server
	def _register_server_packet(self, session_id: int, remote_addr_pair: tuple, raw_packet: bytes, packet_type: int, packet_number: int, packet_keyword: int, payload_words: tuple) -> None:
		# Client is connected to the server
		if self.connected_to_server() is True:
			# Ensure only packet types specific for established sessions are sent
			if packet_type not in [self.PACKET_TYPE_KEEP_ALIVE, self.PACKET_TYPE_DATA]:
				raise Neutrino.NetworkError.UnexpectedPacket('Received unexpected packet type {0} by server (connected).'.format(self._get_default_int_repr(packet_type)))
		
		# Needs to establish connection first
		else:
			# Ensure only packet types specific for unestablished sessions are sent
			if packet_type not in [self.PACKET_TYPE_SERVER_HELLO2]:
				raise Neutrino.NetworkError.UnexpectedPacket('Received unexpected packet type {0} by server (not connected).'.format(self._get_default_int_repr(packet_type)))
				
			# Server confirms session establishment
			if packet_type is self.PACKET_TYPE_SERVER_HELLO2:
				# Store session id locally
				self.client_session_id = session_id
				
				# Trigger event
				self.base_client_event_on_session_establishing(self.client_session_id)
				
				# Send out final handshake packet to explicitly confirm the session establishment
				self._send_to_server(packet_type=self.PACKET_TYPE_CLIENT_HELLO3, session_id=self.client_session_id)
	
		# Update precalculated time when the session ends
		session_timeout = self.SESSION_TIMEOUT_PENDING

		# Will be higher for established sessions
		if self.connected_to_server():
			session_timeout = self.SESSION_TIMEOUT_ESTABLISHED
		
		# Precalculate time when the session ends
		self.client_local_session_expire_time = (self._get_current_time_milliseconds() + session_timeout)	
	
	"""
	SERVER
	"""
	# Register packet from any client
	def _register_client_packet(self, client_id: int, session_id: int, remote_addr_pair: tuple, raw_packet: bytes, packet_type: int, packet_number: int, packet_keyword: int, payload_words: tuple) -> None:
		session_state = self.client_sessions[client_id]['session_state']

		# Client tries to establish a new session by sending
		# unprotected packet PACKET_TYPE_CLIENT_HELLO1.
		if session_state is self.INTERNAL_SESSION_STATE_NONE:
			# Drop any unexpected packets
			if packet_type not in [self.PACKET_TYPE_CLIENT_HELLO1]:
				raise Neutrino.NetworkError.UnexpectedPacket('Received unexpected packet type {0} by unconnected client.'.format(self._get_default_int_repr(packet_type)))
			else:
				# Client cannot have a session id yet
				if session_id is not self.CLIENT_SESSION_ID_PENDING:
					raise Neutrino.ClientError.SessionError('Unconnected client cannot have a session id yet.')
					
				# Client cannot have a packet number yet
				if packet_number is not self.PACKET_NUMBER_PENDING:
					raise Neutrino.ClientError.SessionError('Unconnected client cannot have a packet number yet.')
					
				# Client initializes connection by sending its public key
				if packet_type is self.PACKET_TYPE_CLIENT_HELLO1:
				
					# Hello packets must be padded out to prevent amplification attacks
					packet_size = len(raw_packet)
					
					if packet_size < self.MAX_PACKET_SIZE:
						raise Neutrino.NetworkError.InvalidPacket('Client\'s hello packet size of {0} bytes is too small, expected {1} bytes.'.format(packet_size, self.MAX_PACKET_SIZE))
				
					# Packet has exactly 1 word; extract client's public key
					try:
						(client_public_key,) = self._expect_n_words(payload_words, exactly=1)
					except Neutrino.UnexpectedAmountOfWords:
						raise Neutrino.NetworkError.InvalidPacket('Malformed PACKET_TYPE_CLIENT_HELLO1: Expected exactly one (1) word in payload.') from None
					else:
						# Validate client's public key
						if len(client_public_key) is not self.PUBLIC_KEY_LENGTH:
							raise Neutrino.RemoteCryptoError.InvalidPublicKey('Length of client\'s public key is expected to be exactly {0} bytes.'.format(self.PUBLIC_KEY_LENGTH))		
						
						# Trigger event
						(client_ip, client_port) = remote_addr_pair
						
						# Connection refused
						if self.base_server_event_on_session_request(client_id, session_id, client_ip, client_port) is not True:
							self._unregister_client(self.CLIENT_UNREGISTER_REASON_REFUSED, client_id)
						else:
							# Derive and store per-connection read and write encryption keys
							(self.client_sessions[client_id]['read_key'], self.client_sessions[client_id]['write_key']) = self._derive_server_encryption_keys_from_keypair(self.local_public_key, self.local_secret_key, client_public_key)
							
							# Generate random session id and change session state
							self.client_sessions[client_id]['session_id'] = session_id = self._generate_random_client_session_id()
							self.client_sessions[client_id]['session_state'] = self.INTERNAL_SESSION_STATE_PENDING
							
							# Generate random initial packet number
							self.client_sessions[client_id]['packet_number'] = initial_packet_number = self._generate_initial_random_packet_number()
							
							# Add session id to client session ids list (session_id => client_id)
							self.client_session_ids[session_id] = client_id					
							
							# Confirm session establishment to client
							self._send_to_client(client_id=client_id, packet_type=self.PACKET_TYPE_SERVER_HELLO2, session_id=session_id)
		
		# Client explicitly confirms session establishment by
		# sending encrypted packet PACKET_TYPE_CLIENT_HELLO3.
		elif session_state is self.INTERNAL_SESSION_STATE_PENDING:
			# Drop any unexpected packets
			if packet_type not in [self.PACKET_TYPE_CLIENT_HELLO3]:
				raise Neutrino.NetworkError.UnexpectedPacket('Received unexpected packet type {0} by connected client.'.format(self._get_default_int_repr(packet_type)))
			else:
				# Confirm session establishment
				if packet_type is self.PACKET_TYPE_CLIENT_HELLO3:
					# Update session state
					self.client_sessions[client_id]['session_state'] = self.INTERNAL_SESSION_STATE_ESTABLISHED
					
					# Trigger event
					self.base_server_event_on_session_established(client_id, self.client_sessions[client_id]['session_id'])
		
		# Any other packets after session establishment
		elif session_state is self.INTERNAL_SESSION_STATE_ESTABLISHED:
			# Drop any unexpected packets
			if packet_type not in [self.PACKET_TYPE_KEEP_ALIVE, self.PACKET_TYPE_DATA, self.PACKET_TYPE_CLOSE]:
				raise Neutrino.NetworkError.UnexpectedPacket('Received unexpected packet type {0} by connected client.'.format(self._get_default_int_repr(packet_type)))
			else:
				# Respond to KEEP_ALIVE packet with KEEP_ALIVE packet
				if packet_type is self.PACKET_TYPE_KEEP_ALIVE:
					self._send_keep_alive_packet(client_id=client_id, session_id=session_id)
					
				# Client wants to close the connection
				elif packet_type is self.PACKET_TYPE_CLOSE:
					self._unregister_client(self.CLIENT_UNREGISTER_REASON_CLOSE, client_id)
		
		# As long client did not close the connection (PACKET_TYPE_CLOSE)
		if client_id in self.client_sessions:
			# Update precalculated time when the session ends
			session_timeout = self.SESSION_TIMEOUT_PENDING
			
			# Will be higher for established sessions
			if self.client_sessions[client_id]['session_state'] is self.INTERNAL_SESSION_STATE_ESTABLISHED:
				session_timeout = self.SESSION_TIMEOUT_ESTABLISHED
			
			self.client_sessions[client_id]['local_session_expire_time'] = (self._get_current_time_milliseconds() + session_timeout)
	
	"""
	SERVER / CLIENTS
	"""
	def _send_keep_alive_packet(self, client_id: Optional[int], session_id: Optional[int], payload_words: list=[]) -> None:
		if self.is_client() is True:
			self._send_to_server(packet_type=self.PACKET_TYPE_KEEP_ALIVE, session_id=self.client_session_id, payload_words=payload_words)
		elif self.is_server() is True:
			self._send_to_client(client_id=client_id, packet_type=self.PACKET_TYPE_KEEP_ALIVE, session_id=session_id, payload_words=payload_words)
	
	# Register packet from server or client
	def _register_any_packet(self, client_id: Optional[int], session_id: int, remote_addr_pair: tuple, raw_packet: bytes, packet_type: int, packet_number: int, packet_keyword: int, payload_words: tuple) -> None:
		# Trigger events (they can block the internal <_register_*> events)
		if self.base_event_on_register_any_packet(client_id, session_id, remote_addr_pair, raw_packet, packet_type, packet_number, packet_keyword, payload_words) is not False:
			if self.is_server() is True:
				if self.base_event_on_register_client_packet(client_id, session_id, remote_addr_pair, raw_packet, packet_type, packet_number, packet_keyword, payload_words) is not False:
					self._register_client_packet(client_id, session_id, remote_addr_pair, raw_packet, packet_type, packet_number, packet_keyword, payload_words)
			elif self.is_client() is True:
				if self.base_event_on_register_server_packet(session_id, remote_addr_pair, raw_packet, packet_type, packet_number, packet_keyword, payload_words) is not False:
					self._register_server_packet(session_id, remote_addr_pair, raw_packet, packet_type, packet_number, packet_keyword, payload_words)
	
	"""
	OTHER
	"""
	# Find out if we are the server/client or not
	def is_server(self) -> bool:
		return self.server
		
	def is_client(self) -> bool:
		return (not self.is_server())
		
	# Close this server or client endpoint
	def close(self) -> None:
		self.endpoint.close()
		del self.endpoint
		
	# Just throws an exception if amount of words is
	# not equal to the expected
	def _expect_n_words(self, words: list, exactly: int) -> list:
		if len(words) is not exactly:
			raise Neutrino.UnexpectedAmountOfWords
			
		return words
		
	# Random integer between MIN and MAX
	def _get_random_int(self, min: int, max: int):
		random = secrets.randbelow((max + 1))
		
		if random < min:
			return self._get_random_int(min, max)
			
		return random
		
	# Get n random bytes
	def _get_random_bytes(self, number_of_bytes: int) -> bytes:
		return nacl.utils.random(number_of_bytes)
		
	# Default representation of integers (used for logging purposes)
	def _get_default_int_repr(self, number: int) -> str:
		if number is None:
			return 'None'
			
		return hex(number)
		
	# Get current milliseconds timestamp
	def _get_current_time_milliseconds(self) -> int:
		return int(str(time.time_ns())[:-6])
	
	"""
	DEBUG (Used for debugging purposes)
	"""
	# Get unregister reason name (e.g. "Timeout" for CLIENT_UNREGISTER_REASON_TIMEOUT) by number
	def get_unregister_reason_name_by_number(self, reason: int, prefix: str='CLIENT_UNREGISTER_REASON_') -> str:
		try:
			return prefix + self.CLIENT_UNREGISTER_REASON_NAMES[reason]
		except KeyError:
			return 'UNKNOWN_CLIENT_UNREGISTER_REASON'
		
	# Get packet type name (e.g. string "CLIENT_HELLO1" for PACKET_TYPE_CLIENT_HELLO1)
	def get_packet_name_by_type(self, packet_type: int, prefix: str='PACKET_') -> str:
		try:
			return prefix + self.PACKET_TYPE_NAMES[packet_type]
		except KeyError:
			return 'UNKNOWN_PACKET_TYPE'
	
	"""
	EVENTS
	
	Just inherit this class to use events:
	
		> from Neutrino import Neutrino as NeutrinoSimple
		> class Neutrino(NeutrinoSimple):
		>   def event_*() -> ?:
		>      pass
	"""
	# On every requested frame (after successfull reading or read timeout)
	def base_event_on_requested_frame(self, frame_number: int) -> None:
		return
		
	# Received any unencrypted packet
	def base_event_on_packet_received(self, client_id: Optional[int], session_id: int, remote_addr_pair: tuple, raw_packet: bytes, packet_type: int, packet_number: int, packet_keyword: int, payload_words: list) -> None:
		return
		
	# Sent any packet (encrypted or unprotected)
	def base_event_on_packet_sent(self, client_id: Optional[int], session_id: int, remote_addr_pair: Optional[tuple], raw_packet: bytes, packet_type: int, packet_number: int, packet_keyword: int, payload_words: list) -> None:
		return
		
	# Packet was dropped
	def base_event_on_packet_dropped(self, error_message: str) -> None:
		return
	
	# Packets to be processed after they have been received
	def base_event_on_register_any_packet(self, client_id: Optional[int], session_id: int, remote_addr_pair: tuple, raw_packet: bytes, packet_type: int, packet_number: int, packet_keyword: int, payload_words: tuple) -> bool:
		return True
		
	def base_event_on_register_client_packet(self, client_id: Optional[int], session_id: int, remote_addr_pair: tuple, raw_packet: bytes, packet_type: int, packet_number: int, packet_keyword: int, payload_words: tuple) -> bool:
		return True
		
	def base_event_on_register_server_packet(self, session_id: int, remote_addr_pair: tuple, raw_packet_length: int, raw_packet: bytes, packet_number: int, packet_keyword: int, payload_words: tuple) -> bool:
		return True
	
	"""
	Server-side events
	"""
	# Clients requests new session by sending an unprotected PACKET_TYPE_CLIENT_HELLO1 to the server.
	# Can be blocked by returning False.
	def base_server_event_on_session_request(self, client_id: int, session_id: int, client_ip: str, client_port: int) -> bool:
		return True
	
	# Client confirmed session establishment by responding with a final PACKET_TYPE_CLIENT_HELLO3
	def base_server_event_on_session_established(self, client_id: int, session_id: int) -> None:
		return
		
	# Client unregistered (see CLIENT_UNREGISTER_REASON_*)
	def base_server_event_on_client_unregistered(self, reason: int, client_id: int, session_id: int, client_ip: str, client_port: int) -> None:
		return
		
	# Client's host and/or port changed during session lifetime
	def base_server_event_on_client_addr_change(self, client_id: int, old_client_ip: str, old_client_port: int, new_client_ip: str, new_client_port: int) -> None:
		return
	
	"""
	Client-side events
	"""
	# Client tries to connect to the server by sending an unprotected PACKET_TYPE_CLIENT_HELLO1 to the server.
	def base_client_event_on_request_session(self) -> None:
		return
	
	# Client received encrypted PACKET_TYPE_SERVER_HELLO2, thus, connection to server successfully established. Client is going to respond with a final PACKET_TYPE_CLIENT_HELLO3.
	def base_client_event_on_session_establishing(self, session_id: int) -> None:
		return
	
	"""
	EXCEPTIONS
	"""
	class ConfigurationError(Exception):
		__module__ = Exception.__module__
		
	class LogicError(Exception):
		__module__ = Exception.__module__
		
	class WritingIsLocked(Exception):
		__module__ = Exception.__module__
		
	class LimitExceededError(Exception):
		__module__ = Exception.__module__
		
	class EncodingError(Exception):
		__module__ = Exception.__module__		
		
	class UnexpectedAmountOfWords(Exception):
		__module__ = Exception.__module__
		
	class ClientError(Exception):
		class SessionError(Exception):
			__module__ = Exception.__module__
			
		class NotFoundError(Exception):
			__module__ = Exception.__module__
	
	class NetworkError(Exception):
		class InvalidPacket(Exception):
			__module__ = Exception.__module__
			
		class UnexpectedPacket(Exception):
			__module__ = Exception.__module__
			
		class NotConnected(Exception):
			__module__ = Exception.__module__
	
	class LocalCryptoError(Exception):
		class DecryptionFailed(Exception):
			__module__ = Exception.__module__
			
		class InvalidPublicOrSecretKey(Exception):
			__module__ = Exception.__module__
			
	class RemoteCryptoError(Exception):
		class InvalidPublicKey(Exception):
			__module__ = Exception.__module__
	
	# Not an error or nothing which needs to be considered of
	class Instruction(Exception):
		# Packet which leads to an error (e.g. expired client sessions,
		# malformed packets). Since the server is not able to fix any
		# client side issues, you want to drop all these packets.
		class DropThisPacket(Exception):
			__module__ = Exception.__module__
