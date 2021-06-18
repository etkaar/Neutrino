#!/usr/bin/env python3
'''
Copyright (c) 2021 etkaar <https://github.com/etkaar>

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
from sortedcollections import SortedDict

class Neutrino:
	
	"""
	CONSTANTS
	"""
	# Little-endian
	BYTE_ORDER: str = '<'
	
	# Arbitrary but unique protocol identifier
	PROTOCOL_IDENTIFIER: int = 0x5baa260c
	
	# Protocol version number which may be iterated only after relevent updates
	PROTOCOL_VERSION: int = 0x02
	
	# Header has a left and right part, because the left part must be left unprotected.
	#
	# LEFT : <[Protocol Identifier = u32 bit (4)] [Protocol Version = u8 bit (1)] [Type = u8 bit (1)] [Session ID = u64 bit (8)]>
	# RIGHT: <[Packet Number = u64 bit (8)]>
	HEADER_FORMAT_LEFT: str = 'IBBQ'
	HEADER_FORMAT_RIGHT: str = 'Q'
	
	# Sizes (total header size is 22 bytes)
	HEADER_SIZE_LEFT: int = 4 + 1 + 1 + 8
	HEADER_SIZE_RIGHT: int = 8
	
	TOTAL_HEADER_SIZE: int = (HEADER_SIZE_LEFT + HEADER_SIZE_RIGHT)
	
	# All packages, except the PACKET_TYPE_CLIENT_HELLO, are encrypted
	PACKET_TYPE_CLIENT_HELLO: int = 0x01
	PACKET_TYPE_SERVER_HELLO: int = 0x02
	PACKET_TYPE_KEEP_ALIVE: int = 0x03
	PACKET_TYPE_DATA: int = 0x40
	
	PACKET_TYPES: list = [PACKET_TYPE_CLIENT_HELLO, PACKET_TYPE_SERVER_HELLO, PACKET_TYPE_KEEP_ALIVE, PACKET_TYPE_DATA]
	
	# For best network compatibility, we choose a relatively small
	# UDP packet size; see the QUIC protocol for more information.
	MAX_PACKET_SIZE: int = 1280
	
	# Encryption invokes a small overhead (24 bytes for the nonce, 16 bytes for the encryption header). We need to take care of that once we check the limits.
	PACKET_ENCRYPTION_OVERHEAD: int = (nacl.bindings.crypto_aead.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES + nacl.bindings.crypto_aead.crypto_aead_xchacha20poly1305_ietf_ABYTES)
	
	# Maximum payload size
	MAX_PAYLOAD_SIZE: int = (MAX_PACKET_SIZE - TOTAL_HEADER_SIZE - PACKET_ENCRYPTION_OVERHEAD)
	
	# Padding char
	PACKET_PADDING_CHAR: bytes = b'\x00'
	
	# Max size of sequence number in bit. If you need
	# to change that, you also need to alter HEADER.
	MAX_PACKET_NUMBER_SIZE: int = 2**64-1
	
	INITIAL_PACKET_NUMBER_RANGE_MIN: int = 2**6 # 64
	INITIAL_PACKET_NUMBER_RANGE_MAX: int = 2**31-1
	
	# Packet numbers
	PACKET_NUMBER_NONE: int = 0x01
	PACKET_NUMBER_PENDING: int = 0x02
	
	# Length of public and secret key in bytes
	PUBLIC_KEY_LENGTH: int = nacl.bindings.crypto_kx.crypto_kx_PUBLIC_KEY_BYTES
	SECRET_KEY_LENGTH: int = nacl.bindings.crypto_kx.crypto_kx_SECRET_KEY_BYTES
	
	"""
	CONSTANTS: CLIENTS
	"""
	# Maximum amount of connections in total or for a single client. It does
	# not make any difference, if the session was established or not. Therefore,
	# it is mandatory to remove any information soon if there was no handshake
	# in a very timely manner.
	MAX_CONNECTIONS: int = 2**16 # 65536
	MAX_CONNECTIONS_CLIENT: int = 32
	
	# Sessions
	MIN_SESSION_ID_SIZE: int = 2**6 # 64
	MAX_SESSION_ID_SIZE: int = 2**64-1
	
	INTERNAL_SESSION_STATE_PENDING: int = 0
	INTERNAL_SESSION_STATE_ESTABLISHED: int = 1
	
	CLIENT_SESSION_ID_NONE: int = 0x01
	CLIENT_SESSION_ID_PENDING: int = 0x02	
	
	# Time in seconds after a session is destroyed when there are no packets received
	SESSION_TIMEOUT_PENDING: float = 0.25
	SESSION_TIMEOUT_ESTABLISHED: float = 1.0
	
	# Clients
	MAX_LOCAL_CLIENT_ID_SIZE: int = 2**64-1
	
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
	
	# Debug mode 
	debug = False
	
	# Fake network problems
	fake_lost_packets = False
	
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
	client_local_session_expire_time: float = 0.0
	
	# Time of the very last packet we sent; used to prevent
	# unnecessarily KEEP_ALIVE packets.
	client_last_packet_sent_time: float = 0.0
	
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
	SERVERS_TICK_TIME: float = 0.2
	CLIENTS_TICK_TIME: float = 0.2
	
	last_tick_time: float = 0.0
	
	"""
	QUEUES
	"""
	retained_packets_out: list = []
	
	"""
	DEBUG (Used for debugging purposes)
	"""
	PACKET_TYPE_NAMES: dict = {
		PACKET_TYPE_CLIENT_HELLO: 'CLIENT_HELLO',
		PACKET_TYPE_SERVER_HELLO: 'SERVER_HELLO',
		PACKET_TYPE_KEEP_ALIVE: 'KEEP_ALIVE',
		PACKET_TYPE_DATA: 'DATA'
	}

	"""
	INITIALIZATION
	"""
	# Empty to make inheritance easier
	def __init__(self):
		pass
	
	# Initialize endpoint with host and port
	def init(self, host: str, port: int, server: bool=False, debug: bool=False):
		self.host = host
		self.port = port
		self.server = server
		self.debug = debug
		
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
	
		# Encode and decode a packet
		#byte_words = [b'Apfel essen Hunde', b'Banane trinken Fliegen', b'So oder\x00 so']
		
		#packet_encoded = self._encrypt_and_encode_packet(packet_type=self.PACKET_TYPE_CLIENT_HELLO, packet_number=1, session_id=self.CLIENT_SESSION_ID_PENDING, byte_words=byte_words, padding=-1)
		#packet_decoded = self._decrypt_and_decode_packet(packet_encoded)
		
		#print('packet_encoded', len(packet_encoded), packet_encoded)
		#print('packet_decoded', len(packet_decoded), packet_decoded)
	
	
	"""
	LOOP & TICKERS
	"""
	# Handles all incoming packets forever
	def loop(self):
		
		while True:
		
			# Trigger event
			self.event_on_loop_frame()
		
			"""
			::TICKERS
			"""
			if self.is_server() is True:
				self._servers_tick()
			else:
				self._clients_tick()
			
			"""
			<<READ
			"""
			for (key, mask) in self.selector.select(timeout=0.2):
				# Receive next UDP packet
				try:
					# <<ANY CLIENT
					if self.is_server() is True:
						(client_id, session_id, remote_addr_pair, raw_packet, packet_type, packet_number, payload_words) = self._get_next_packet_from_any_client()
						self._register_client_packet(client_id, len(raw_packet), packet_type, packet_number, session_id, payload_words)
					
					# <<SERVER
					elif self.is_client() is True:
						(session_id, remote_addr_pair, raw_packet, packet_type, packet_number, payload_words) = self._get_next_packet_from_the_server()
						self._register_server_packet(len(raw_packet), packet_type, packet_number, session_id, payload_words)
				
				# Silently drop and trigger event
				except Neutrino.Instruction.DropThisPacket as message:
					self.event_on_packet_dropped(message)
			
			"""
			>>WRITE
			"""
			# Hold packets back as long the session to the server is not established
			if (self.is_server() is True) or (self.is_client() is True and self.is_this_client_authenticated_to_server() is True):
				
				# All packets
				while len(self.retained_packets_out) > 0:
					# Earliest retained packet
					(client_id, raw_packet) = self.retained_packets_out.pop(0)
					
					try:
						if self.is_server() is True:
							remote_addr_pair = self._get_client_addr_by_client_id(client_id)
						elif self.is_client() is True:
							remote_addr_pair = (self.host, self.port)
					except Neutrino.ClientError.NotFoundError:
						raise Neutrino.ClientError.NotFoundError
					else:
						self._write(remote_addr_pair, raw_packet)

	def _servers_tick(self):
		# Five times per second
		if self.last_tick_time + self.SERVERS_TICK_TIME < time.time():
			self.last_tick_time = time.time()
			
			# Remove all timed out client connections
			self._remove_all_timed_out_clients()
		
	def _clients_tick(self):
		# Five times per second
		if self.last_tick_time + self.CLIENTS_TICK_TIME < time.time():
			self.last_tick_time = time.time()
			
			# Invalidate session once expired
			if self.client_local_session_expire_time < time.time():
				self.client_session_id = None
				self.client_packet_number = None
				
				if self.client_local_session_expire_time > 0:
					print(">>SESSION TO SERVER EXPIRED")
				else:
					print(">>FAILED TO ESTABLISH SESSION")
					
				self.client_local_session_expire_time = 0.0
			
			# Authenticate and establish encrypted connection session
			if self.is_this_client_authenticated_to_server() is False:
				self.authenticate_to_server()
			else:
				# Periodically send KEEP_ALIVE packets to validate the connection
				if self.client_last_packet_sent_time + (self.SESSION_TIMEOUT_ESTABLISHED) < time.time():
					self._client_KEEP_ALIVE()
		
		
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
		
	# Encrypt encoded package (= encode and then encrypt)
	def _encrypt_encoded_packet(self, raw_key: bytes, raw_packet: bytes) -> bytes:
		# Header is partially encrypted and payload is fully encrypted
		(left_unprotected, right_encrypted) = (raw_packet[0:self.HEADER_SIZE_LEFT], raw_packet[self.HEADER_SIZE_LEFT:])
		
		# Encrypt right part
		right_encrypted = self._encrypt_plaintext_by_key(raw_key=raw_key, plaintext=right_encrypted)
		
		# Concatenate unprotected and encrypted parts
		raw_packet_encrypted = left_unprotected + right_encrypted
		
		return raw_packet_encrypted
	
	# Encode packet from raw bytes words (this does not take care of UTF-8 encodes strings)
	def _encode_packet(self, packet_type: int, packet_number: int, session_id: int, byte_words: list=[], padding: int=0):
		if type(byte_words) is not list:
			raise Neutrino.EncodingError("'byte_words' must be a list, containing items of type 'bytes'.")
		
		# Start with the number of words
		payload_bytes = self._pack('B', len(byte_words))
		
		for byte_word in byte_words:
			if type(byte_word) is not bytes:
				raise Neutrino.EncodingError("Item in list 'byte_words' must be of type 'bytes': {0}".format(byte_word))
			
			payload_bytes += self._pack('H', len(byte_word))
			payload_bytes += byte_word
			
		# Ensure that max payload size (and thus max packet size) is not exceeded
		payload_size = len(payload_bytes)
		
		if payload_size > self.MAX_PAYLOAD_SIZE:
			raise Neutrino.EncodingError('Payload size of this packet ({0} bytes) would exceed maximum size of {1} bytes.'.format(payload_size, self.MAX_PAYLOAD_SIZE))
			
		# Create header
		raw_packet = b''
		raw_packet += self._pack(self.HEADER_FORMAT_LEFT, self.PROTOCOL_IDENTIFIER, self.PROTOCOL_VERSION, packet_type, session_id)
		raw_packet += self._pack(self.HEADER_FORMAT_RIGHT, packet_number)
		
		# Just append bytes payload to the header instead of packing it
		raw_packet += payload_bytes
		
		# Pad out packet until max size is reached
		if padding is -1:
			raw_packet += (self.MAX_PACKET_SIZE - len(raw_packet)) * self.PACKET_PADDING_CHAR
		
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
		
	# Decode the (usually previously) decrypted right part of the packet header
	def _decode_and_validate_decrypted_packet_header(self, raw_packet: bytes) -> tuple:
		try:
			(packet_number,) = self._unpack(self.HEADER_FORMAT_RIGHT, raw_packet[self.HEADER_SIZE_LEFT:(self.HEADER_SIZE_LEFT + self.HEADER_SIZE_RIGHT)])
		except struct.error as message:
			raise Neutrino.NetworkError.InvalidPacket(('Malformed header (decrypted part).', message)) from None
			
		return (packet_number,)
		
	# Decode the (usually previously) decrypted payload of the packet
	def _decode_and_validate_decrypted_packet_payload(self, raw_packet: bytes) -> tuple:
		# Payload is the rest of the packet
		payload_bytes = raw_packet[self.TOTAL_HEADER_SIZE:]	
		
		# No payload
		payload_bytes_size = len(payload_bytes)
		
		if payload_bytes_size == 0:
			raise Neutrino.NetworkError.InvalidPacket('Empty payload given.')
		
		# Get amount of words (u8 bit = 1 byte)
		(amount_of_byte_words,) = self._unpack('B', payload_bytes[0:1])
		
		'''
		if amount_of_byte_words == 0:
			raise Neutrino.NetworkError.InvalidPacket('Payload does not contain any words.')
		'''
		# Place offset after [Number of Words = u8 bit (1)]
		offset = 1
		
		# Extract all byte words
		byte_words = []
		
		for x in range(0, amount_of_byte_words):
			try:
				# Word length ([Word Length = u16 bit (2)])
				(byte_word_length,) = self._unpack('H', payload_bytes[offset:(offset + 2)])
				offset += 2
				
				# Byte word ([Word = ? bit])
				byte_words.append(payload_bytes[offset:(offset + byte_word_length)])
				offset += byte_word_length
			except struct.error as e:
				raise Neutrino.NetworkError.InvalidPacket(('Malformed payload (total size: {0} bytes).'.format(payload_bytes_size), e)) from None
		
		# Remove any trailing padding chars
		payload_bytes = payload_bytes.rstrip(self.PACKET_PADDING_CHAR)
		
		# Make sure that we unpacked the whole payload
		payload_bytes_size = len(payload_bytes)
		
		if offset < payload_bytes_size:
			raise Neutrino.NetworkError.InvalidPacket('Could not extract all words from payload. Payload may contain unexpected bytes (total size: {0} bytes).'.format(payload_bytes_size))
		
		return byte_words
	
	
	"""
	NETWORK: READ
	"""
	def _read(self) -> tuple:
		# All or nothing: Receive n bytes of the next UDP
		# packet and discard any remaining bytes.
		# 
		# (However, at this point, we would always fetch the
		# maximum for a UDP package which is 64 KiB).
		#
		# Throws BlockingIOError in non-blocking mode, if
		# there are no packets left to read.
		(raw_packet, remote_addr_pair) = self.endpoint.recvfrom(2**16)
		
		raw_packet_size = len(raw_packet)
		
		if raw_packet_size > self.MAX_PACKET_SIZE:
			raise Neutrino.NetworkError.InvalidPacket('Size of this packet ({0} bytes) exceeds maximum size of {1} bytes.'.format(raw_packet_size, self.MAX_PACKET_SIZE))
		
		# Decode and validate only unprotected header parts and validate total header size
		(packet_type, session_id) = self._decode_and_validate_unprotected_packet_header(raw_packet)
		
		return (remote_addr_pair, raw_packet, packet_type, session_id)
	
	# Servers read function
	def _servers_read(self) -> tuple:
		((client_ip, client_port), raw_packet, packet_type, session_id) = self._read()
		
		# Only, if session id must be given
		if self._is_not_pending_client_session_id(session_id):
			# Try to get client id by session id
			client_id = self._get_client_id_by_session_id(session_id)
	
			# Find out the secret encryption (write) key
			raw_key = self._get_client_session_read_key_by_client_id(client_id)
		
			# Encrypted encoded package => Decrypted encoded package
			try:
				raw_packet = self._decrypt_encoded_packet(raw_key=raw_key, raw_packet=raw_packet)
			except Neutrino.LocalCryptoError.DecryptionFailed:
				raise Neutrino.LocalCryptoError.DecryptionFailed('Failed to decrypt packet of client <client_id:session_id> <{0:1}.'.format(self._get_int_repr(client_id), self._get_int_repr(session_id)))
				
			# Update current host and port of the client
			self._update_client_addr(client_id, client_ip, client_port)
		
		# Decode and validate the part of the decrypted protected header
		(packet_number,) = self._decode_and_validate_decrypted_packet_header(raw_packet)	
		
		# Decode and validate decrypted package
		payload_words = self._decode_and_validate_decrypted_packet_payload(raw_packet)
		
		# Get existing client
		try:
			client_id = self._get_client_id_by_addr(client_ip, client_port)
			'''
			# Client timed out
			difference = time.time() - self.client_sessions[client_id]['local_session_expire_time']
			
			if difference > 0:
				raise Neutrino.ClientError.SessionError('Client has timed out {0} ms ago.'.format(int(difference * 1000)))
			'''
		# Add client
		except Neutrino.ClientError.NotFoundError:
			client_id = self._add_client_id_by_addr(client_ip, client_port)		
		
		# Will be lower for pending sessions
		session_timeout = self.SESSION_TIMEOUT_ESTABLISHED
		
		# If not existent: Register (but not establish yet) client session.
		# (The client ip address can still be spoofed)
		if client_id not in self.client_sessions:
		
			# Register client
			self.client_sessions[client_id] = {
				# Remote addr
				'ip': client_ip,
				'port': client_port,
				
				# Session
				'session_id': None,
				'session_state': self.INTERNAL_SESSION_STATE_PENDING,
				
				# Cryptographic read and write keys derived from the clients
				# public key. These keys change for every connection.
				'read_key': b'',
				'write_key': b'',
				
				# Current packet number
				'packet_number': None
			}
			
			session_timeout = self.SESSION_TIMEOUT_PENDING
		
		# Precalculate time when the session ends
		self.client_sessions[client_id]['local_session_expire_time'] = (time.time() + session_timeout)		
		
		# Trigger event
		self.event_on_any_packet_received(client_id, session_id, (client_ip, client_port), packet_type, packet_number, payload_words)		
		
		return (client_id, session_id, (client_ip, client_port), raw_packet, packet_type, packet_number, payload_words)
		
	# Clients read function
	def _clients_read(self) -> tuple:
		(remote_addr_pair, raw_packet, packet_type, session_id) = self._read()
		
		# Only, if session id must be given
		if self._is_not_pending_client_session_id(session_id):
			# Encrypted encoded package => Decrypted encoded package
			raw_packet = self._decrypt_encoded_packet(raw_key=self.client_read_key, raw_packet=raw_packet)
		
		# Decode and validate the part of the decrypted protected header
		(packet_number,) = self._decode_and_validate_decrypted_packet_header(raw_packet)	
		
		# Decode and validate decrypted package
		payload_words = self._decode_and_validate_decrypted_packet_payload(raw_packet)
		
		# Will be lower for pending sessions
		session_timeout = self.SESSION_TIMEOUT_ESTABLISHED

		if not self.is_this_client_authenticated_to_server():
			session_timeout = self.SESSION_TIMEOUT_PENDING
		
		# Precalculate time when the session ends
		self.client_local_session_expire_time = (time.time() + session_timeout)
		
		# Trigger event
		self.event_on_any_packet_received(None, session_id, remote_addr_pair, packet_type, packet_number, payload_words)
		
		return (session_id, remote_addr_pair, raw_packet, packet_type, packet_number, payload_words)
		
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
		# Sent time of the very last packet
		if self.is_client() is True:
			self.client_last_packet_sent_time = time.time()
		
		if self.fake_lost_packets is True:
			if int(time.time()) % 10 == 0:
				return 0
		
		return self.endpoint.sendto(raw_packet, remote_addr_pair)
	
	# Send packet to any endpoint
	def _send_packet(self, instantly: bool, client_id: Optional[int], remote_addr_pair: Optional[tuple], packet_type: int, packet_number: int, session_id: int, byte_words: list=[], padding: int=0) -> tuple:
		# Ensure client_id is given if endpoint is the server
		if self.is_server() is True and client_id is None:
			raise Neutrino.LogicError("'client_id' cannot be None if packet is sent to a client.")
			
		# Get ip and port of client
		if client_id is not None:
			remote_addr_pair = self._get_client_addr_by_client_id(client_id)
			
		# Create encoded packet
		raw_packet = self._encode_packet(packet_type, packet_number, session_id, byte_words, padding)
		
		# As long it is not the initial client's HELLO packet
		if packet_type not in [self.PACKET_TYPE_CLIENT_HELLO]:
		
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
		if instantly is True:
			self._write(remote_addr_pair, raw_packet)
		else:
			# Using the client's id instead of the remote_addr_pair allows us
			# sending packets even if endpoint addr, but not session id has changed.
			self._retain_outgoing_packet(client_id, raw_packet)
			
		# Trigger event
		self.event_on_packet_sent(client_id, remote_addr_pair, raw_packet, byte_words, packet_type, packet_number, session_id)
		
		# Return packet number
		return (raw_packet, packet_number)
		
	# Send packet to a client
	def _send_to_client(self, instantly: bool, client_id: int, packet_type: int, session_id: int, byte_words: list=[], padding: int=0) -> tuple:
		# Get current clients session package number and increase it afterwards
		packet_number = self._get_servers_client_session_packet_number(client_id=client_id, increase=True)
		
		# Send packet to client
		return self._send_packet(instantly, client_id, None, packet_type, packet_number, session_id, byte_words, padding)

	# Send packet to the server
	def _send_to_server(self, instantly: bool, packet_type: int, session_id: int, byte_words: list=[], padding: int=0) -> tuple:
		packet_number = self.PACKET_NUMBER_PENDING
		
		# As long it is not the initial client's HELLO packet
		if packet_type not in [self.PACKET_TYPE_CLIENT_HELLO]:
			# Get current clients package number and increase it afterwards
			packet_number = self._get_clients_packet_number(increase=True)
		
		# Send packet to server
		return self._send_packet(instantly, None, (self.host, self.port), packet_type, packet_number, session_id, byte_words, padding)
		
	# Put outgoing packet into sending queue
	def _retain_outgoing_packet(self, client_id: Optional[int], raw_packet: bytes) -> None:
		self.retained_packets_out.append((client_id, raw_packet))
		
		
	"""
	CLIENTS
	"""
	# Authenticate to the server
	def authenticate_to_server(self):
		# Generate new client keypair for each connection attempt
		self._reload_local_crypto_keys()
	
		print(">>authenticate_to_server", self.CLIENT_SESSION_ID_PENDING, self.client_session_id)
		# Send HELLO packet to server to establish the encrypted connection.
		# The initial HELLO packet must be padded out to prevent amplification attacks.
		self._send_to_server(instantly=True, packet_type=self.PACKET_TYPE_CLIENT_HELLO, session_id=self.CLIENT_SESSION_ID_PENDING, byte_words=[self.get_local_public_key()], padding=-1)
	
	# Send KEEP_ALIVE to server to keep session
	def _client_KEEP_ALIVE(self):
		self._send_to_server(instantly=False, packet_type=self.PACKET_TYPE_KEEP_ALIVE, session_id=self.client_session_id)
	
	# Pass through all clients and delete all information about clients which timed out
	def _remove_all_timed_out_clients(self):
		for client_id in list(self.client_sessions):
			if self.client_sessions[client_id]['local_session_expire_time'] < time.time():
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
				self.event_on_client_timed_out(client_id, session_id, client_ip, client_port)
	
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
			raise Neutrino.ClientError.NotFoundError('No client session identified by <client_id> (<{0}>) found.'.format(self._get_int_repr(client_id))) from None
	
	# Get client id by session id
	def _get_client_id_by_session_id(self, session_id: int) -> int:
		try:
			return self.client_session_ids[session_id]
		except KeyError:
			raise Neutrino.ClientError.NotFoundError('No client identified by <session_id> (<{0}>) found.'.format(self._get_int_repr(session_id))) from None	
	
	# Get client's session secret encryption read/write key by client id
	def _get_client_session_read_key_by_client_id(self, client_id: int) -> bytes:
		try:
			return self.client_sessions[client_id]['read_key']
		except KeyError:
			raise Neutrino.ClientError.NotFoundError('No client session identified by <client_id> (<{0}>) found.'.format(self._get_int_repr(client_id))) from None
	
	def _get_client_session_write_key_by_client_id(self, client_id: int) -> bytes:
		try:
			return self.client_sessions[client_id]['write_key']
		except KeyError:
			raise Neutrino.ClientError.NotFoundError('No client session identified by <client_id> (<{0}>) found.'.format(self._get_int_repr(client_id))) from None
	
	# Add new client id using the given addr pair
	def _add_client_id_by_addr(self, client_ip: str, client_port: int) -> int:
		# Limit of total connections
		if (len(self.client_client_ids) + 1) > self.MAX_CONNECTIONS:
			raise Neutrino.LimitExceededError('Adding new client would exceed total connections limit of {0}.'.format(self.MAX_CONNECTIONS))
		
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
			self.event_on_client_addr_change(client_id, old_client_ip, old_client_port, new_client_ip, new_client_port)
	
	# Get (and possibly increase) the servers packet number for a specific client session
	def _get_servers_client_session_packet_number(self, client_id: int, increase: bool=False):
		packet_number = self.client_sessions[client_id]['packet_number']
		
		if increase is True:
			self.client_sessions[client_id]['packet_number'] += 1
			
		return packet_number
	
	# Get (and possibly increase) the clients sending packet number
	def _get_clients_packet_number(self, increase: bool=False):
		# Generate initial random packet number which is used
		# for packets sent to the server
		if self.client_packet_number is None:
			self.client_packet_number = self._generate_initial_random_packet_number()
			
		packet_number = self.client_packet_number
		
		if increase is True:
			self.client_packet_number += 1
			
		return packet_number
		
	# Generate random client id for local use (64 bit)
	def _generate_random_local_client_id(self) -> int:
		return self._get_random_int(0, self.MAX_LOCAL_CLIENT_ID_SIZE)		
		
	# Generate random session id (64 bit)
	def _generate_random_client_session_id(self) -> int:
		return self._get_random_int(self.MIN_SESSION_ID_SIZE, self.MAX_SESSION_ID_SIZE)
	
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
	
	# Check if client endpoint is authenticated to the server
	def is_this_client_authenticated_to_server(self):
		if self.client_session_id is not None:
			return True
	
		return False
		
	# Register packet from the server
	def _register_server_packet(self, raw_packet_length: int, packet_type: int, packet_number: int, session_id: int, payload_words: tuple) -> None:
		# Server confirms session establishment
		if packet_type is self.PACKET_TYPE_SERVER_HELLO:
			if self.is_this_client_authenticated_to_server() is True:
				raise Neutrino.ClientError.SessionError('This client endpoint is already authenticated.')
			
			self.client_session_id = session_id
			
			# Send KEEP_ALIVE to implicitly confirm the session establishment;
			# otherwise the session timeout will not increase and the server
			# will close the session very soon.
			self._client_KEEP_ALIVE()
			
			# Trigger event
			self.event_on_authenticated_to_server(self.client_session_id)
	
	"""
	SERVER
	"""
	# Register packet from any client
	def _register_client_packet(self, client_id: int, raw_packet_length: int, packet_type: int, packet_number: int, session_id: int, payload_words: tuple) -> None:
		# Validate session for connected clients
		if self.client_sessions[client_id]['session_state'] is self.INTERNAL_SESSION_STATE_ESTABLISHED:
			
			# Send back KEEP_ALIVE packets
			if packet_type is self.PACKET_TYPE_KEEP_ALIVE:
				self._send_to_client(instantly=False, client_id=client_id, packet_type=self.PACKET_TYPE_KEEP_ALIVE, session_id=session_id)
				
		# Unconnected clients
		else:
		
			# Client cannot have a session id yet
			if session_id is not self.CLIENT_SESSION_ID_PENDING:
				raise Neutrino.ClientError.SessionError('Unconnected client cannot have a session id yet.')
				
			# Client cannot have a packet number yet
			if packet_number is not self.PACKET_NUMBER_PENDING:
				raise Neutrino.ClientError.SessionError('Unconnected client cannot have a packet number yet.')
				
			# Client initializes connection by sending its public key
			# NOTE: Blocks any other packets, see [1].
			if packet_type is self.PACKET_TYPE_CLIENT_HELLO:
			
				# Hello packets must be padded out to prevent amplification attacks.
				if raw_packet_length < self.MAX_PACKET_SIZE:
					raise Neutrino.NetworkError.InvalidPacket('Client\'s hello packet too small, expected {0} bytes.'.format(self.MAX_PACKET_SIZE))
			
				# Packet has exactly 1 word; extract client's public key
				try:
					(client_public_key,) = self._expect_n_words(payload_words, 1)
				except Neutrino.UnexpectedAmountOfWords:
					raise Neutrino.NetworkError.InvalidPacket('Invalid client hello packet.')
				else:
					# Validate client's public key
					if len(client_public_key) is not self.PUBLIC_KEY_LENGTH:
						raise Neutrino.RemoteCryptoError.InvalidPublicKey('Length of client\'s public key is expected to be exactly {0} bytes.'.format(self.PUBLIC_KEY_LENGTH))		
					
					# Derive and store per-connection read and write encryption keys
					(self.client_sessions[client_id]['read_key'], self.client_sessions[client_id]['write_key']) = self._derive_server_encryption_keys_from_keypair(self.local_public_key, self.local_secret_key, client_public_key)
					
					# Generate random session id and change session state
					self.client_sessions[client_id]['session_id'] = session_id = self._generate_random_client_session_id()
					self.client_sessions[client_id]['session_state'] = self.INTERNAL_SESSION_STATE_ESTABLISHED
					
					# Generate random initial packet number
					self.client_sessions[client_id]['packet_number'] = initial_packet_number = self._generate_initial_random_packet_number()
					
					# Add session id to client session ids list (session_id => client_id)
					self.client_session_ids[session_id] = client_id					
					
					# Confirm session establishment to client
					self._send_to_client(instantly=True, client_id=client_id, packet_type=self.PACKET_TYPE_SERVER_HELLO, session_id=session_id)
					
					# Trigger event
					self.event_on_client_session_established(client_id, session_id)
			
			# [1] If client is not connected yet, drop any packages which
			# are not used only to establish the connection
			else:
				raise Neutrino.ClientError.SessionError('Unconnected clients may only transmit their public key.')
		
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
	def _expect_n_words(self, words: list, expected_amount: int) -> list:
		if len(words) is not expected_amount:
			raise Neutrino.UnexpectedAmountOfWords
			
		return words
		
	# Random integer between MIN and MAX
	def _get_random_int(self, min: int, max: int):
		random = secrets.randbelow(max)
		
		if random < min:
			return self._get_random_int(min, max)
			
		return random
		
	# Get n random bytes
	def _get_random_bytes(self, number_of_bytes: int) -> bytes:
		return nacl.utils.random(number_of_bytes)
		
	# Default representation of integers (used for logging purposes)
	def _get_int_repr(self, number: int) -> str:
		return hex(number)
		
	"""
	DEBUG (Used for debugging purposes)
	"""
	# Get packet type name (e.g. string "CLIENT_HELLO" for PACKET_TYPE_CLIENT_HELLO)
	def get_packet_name_by_type(self, packet_type: int) -> str:
		return self.PACKET_TYPE_NAMES[packet_type]
	
	"""
	EVENTS
	
	Just inherit this class to use events:
	
		> from Neutrino import Neutrino as NeutrinoEx
		> class Neutrino(NeutrinoEx):
		>   def event_*():
		>      pass
	"""
	# On every loop frame
	def event_on_loop_frame(self) -> None:
		return
		
	# Received any unencrypted packet
	def event_on_any_packet_received(self, client_id: Optional[int], session_id: int, remote_addr_pair: tuple, packet_type: int, packet_number: int, payload_words: tuple) -> None:
		return
		
	# Sent any packet (encrypted or unprotected)
	def event_on_packet_sent(self, client_id: Optional[int], remote_addr_pair: Optional[tuple], raw_packet: bytes, byte_words: list, packet_type: int, packet_number: int, session_id: int) -> None:
		return
		
	# Packet was dropped
	def event_on_packet_dropped(self, error_message: str) -> None:
		return
		
	# Session for a client established
	def event_on_client_session_established(self, client_id: int, session_id: int) -> None:
		return
		
	# Session to server from client established
	def event_on_authenticated_to_server(self, session_id: int) -> None:
		return
		
	# Client timed out
	def event_on_client_timed_out(self, client_id: int, session_id: int, client_ip: str, client_port: int) -> None:
		return
		
	# Client's host and/or port changed during session lifetime
	def event_on_client_addr_change(self, client_id: int, old_client_ip: str, old_client_port: int, new_client_ip: str, new_client_port: int) -> None:
		return
	
	"""
	Exceptions
	"""
	class LogicError(Exception):
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
		# malformed packages). Since the server is not able to fix any
		# client side issues, you want to drop all these packets.
		class DropThisPacket(Exception):
			__module__ = Exception.__module__