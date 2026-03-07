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
from typing import Optional

"""
Monitors the network traffic. Used for debugging/testing purposes.
"""
class Monitoring:	
	"""
	CONSTANTS
	"""
	# Packets with these types won't be monitored
	SUPPRESS_LIST_PACKET_TYPES: list = [
		# PACKET_TYPE_KEEP_ALIVE
		#0x04
	]
	
	# A raw packet exceeding this length is trunacted
	MAX_VISIBLE_RAW_PACKET_SIZE: int = 32
	
	# A payload word exceeding this length is trunacted
	MAX_VISIBLE_PAYLOAD_SIZE: int = 32
	
	# Max amount of payload words shown
	MAX_AMOUNT_OF_PAYLOADS_SHOWN: int = 8

	# Text and background colors
	TEXT_COLOR: dict = {
		'DEFAULT': '\033[39m',
		'BLACK': '\033[30m',
		
		'LIGHT_GRAY': '\033[37m',
		'LIGHT_RED': '\033[91m',
		'LIGHT_GREEN': '\033[92m',
		'LIGHT_BLUE': '\033[94m',
		'LIGHT_MAGENTA': '\033[95m',
		'LIGHT_CYAN': '\033[96m',
		
		'WHITE': '\033[97m'
	}
	
	BG_COLOR: dict = {
		'DEFAULT': '\033[49m',
		
		'LIGHT_RED': '\033[101m',
		'LIGHT_GREEN': '\033[102m',
		'LIGHT_BLUE': '\033[104m',
		'LIGHT_MAGENTA': '\033[105m',
		'LIGHT_CYAN': '\033[106m',
		
		'BLACK': '\033[40m',
		'WHITE': '\033[107m'
	}
	
	RESET_COLOR: str = '\033[0m'

	# Names
	LOG_NAME_INIT: int = 1
	LOG_NAME_STATUS: int = 2
	LOG_NAME_SEND: int = 3
	LOG_NAME_RECV_UNRELIABLE: int = 4
	LOG_NAME_RECV_RELIABLE: int = 5
	LOG_NAME_DROPPED: int = 6
	LOG_NAME_QUIT: int = 7
	LOG_NAME_RETR: int = 8
	LOG_NAME_DUPLICATE: int = 9
	
	LOG_NAME_APP: int = 10
	
	LOG_NAMES: dict = {
		LOG_NAME_INIT: ['  INIT  ', BG_COLOR['LIGHT_CYAN'], TEXT_COLOR['BLACK']],
		LOG_NAME_STATUS: [' STATUS ', BG_COLOR['LIGHT_CYAN'], TEXT_COLOR['BLACK']],
		LOG_NAME_SEND: [' ► SEND ', BG_COLOR['LIGHT_BLUE'], TEXT_COLOR['WHITE']],
		LOG_NAME_RECV_UNRELIABLE: [' ❓RECV ', BG_COLOR['LIGHT_MAGENTA'], TEXT_COLOR['BLACK']],
		LOG_NAME_RECV_RELIABLE: [' ✅RECV ', BG_COLOR['LIGHT_MAGENTA'], TEXT_COLOR['BLACK']],
		LOG_NAME_DROPPED: [' ❌DROP ', BG_COLOR['LIGHT_RED'], TEXT_COLOR['WHITE']],
		LOG_NAME_QUIT:[' ❌EXIT ', BG_COLOR['LIGHT_RED'], TEXT_COLOR['WHITE']],
		LOG_NAME_RETR:['  RETR  ', BG_COLOR['LIGHT_RED'], TEXT_COLOR['WHITE']],
		LOG_NAME_DUPLICATE:[' DUPLIC ', BG_COLOR['LIGHT_RED'], TEXT_COLOR['WHITE']],
		
		LOG_NAME_APP:[' ■ APP  ', BG_COLOR['LIGHT_GREEN'], TEXT_COLOR['BLACK']]
	}
	
	"""
	VARIABLES
	"""
	monitoring_started: int = 0
	
	# Empty to make inheritance easier
	def __init__(self):
		super().__init__()
		
		self.monitoring_started = self._get_current_time_milliseconds()
	
	# Get time in milliseconds passed since monitoring has started
	def _get_milliseconds_passed(self) -> int:
		return (self._get_current_time_milliseconds() - self.monitoring_started)
	
	# Adds leading zeros before a number and return a string
	def _add_leading_zeros(self, max_total_length: int, number: int) -> str:
		number = str(number)
		amount_of_zeros = (max_total_length - len(number))
		
		if amount_of_zeros < 0:
			amount_of_zeros = 0
		
		return ('0' * amount_of_zeros) + number
		
	# Format message with color
	def color(self, message: str, text_color: str='DEFAULT', bg_color: str='DEFAULT', padding: str='') -> str:
		return self.BG_COLOR[bg_color] + self.TEXT_COLOR[text_color] + padding + message + padding + self.RESET_COLOR
		
	# Log
	def log(self, log_name: int, status_message: Optional[str], key_values: Optional[dict]) -> None:
		message = ''
		
		if self.is_server() is True:
			message += self.color(' Server ', text_color='WHITE', bg_color='LIGHT_BLUE') + ' '
		else:
			message += self.color(' Client ', text_color='WHITE', bg_color='LIGHT_BLUE') + ' '
		
		
		# The client id (CID) is only an internal value for the server which
		# is not transmitted to the opposite endpoint. For the client, the CID
		# will be always 'None' or -1, because it is the server. Therefore, we
		# remove that value from the log.
		if self.is_client() is True:
			if 'Client ID' in key_values:
				del key_values['Client ID']
		
		# Colored prefix
		message += self.LOG_NAMES[log_name][1] + self.LOG_NAMES[log_name][2] + self.LOG_NAMES[log_name][0] + self.RESET_COLOR + ' '
		
		# Time
		timestamp_formatted = str(self._get_current_time_milliseconds())[7:-4] + ' ' + str(self._get_current_time_milliseconds())[9:]
		message += self.color(timestamp_formatted, text_color='LIGHT_GRAY') + ' '
		
		# Any status message (or nothing)
		if status_message is not None:
			message += self.color(status_message, text_color='LIGHT_CYAN')
			
			if key_values:
				message += ' – '
		
		# E.g. packet size and number, payload
		if key_values:
			message += self.create_colored_key_values_string(key_values)
		
		print(message)
		
	# Create a trunacted representation of the payload words
	def _get_payload_representation(self, payload_words: list=[]) -> str:
		representation_list = []
		
		amount_of_words = len(payload_words)
		
		for x in range(min(amount_of_words, self.MAX_AMOUNT_OF_PAYLOADS_SHOWN)):
			word_representation = ''
			
			byte_word = payload_words[x]
			word_size = len(byte_word)
			
			word_representation += "'"
			
			if word_size > self.MAX_VISIBLE_PAYLOAD_SIZE:
				start = self._bytes_to_string(byte_word[:int(self.MAX_VISIBLE_PAYLOAD_SIZE / 2)])
				end = self._bytes_to_string(byte_word[(-1) * int(self.MAX_VISIBLE_PAYLOAD_SIZE / 2):])
				
				word_representation += start.rstrip()
				word_representation += '...'
				word_representation += end.lstrip()
			else:
				word_representation += self._bytes_to_string(byte_word)
				
			word_representation += "'"
			word_representation += ' ({0} bytes)'.format(word_size)
			
			representation_list.append(word_representation)
		
		full_representation = '[' + ', '.join(representation_list) + ']'
		
		# Show how many payload words aren't shown due to the limit
		remaining_words = amount_of_words - self.MAX_AMOUNT_OF_PAYLOADS_SHOWN
		
		if remaining_words > 0:
			full_representation += ' +{0} word(s) remaining.'.format(remaining_words)
		
		return full_representation
		
	# Create a trunacted raw packet representation
	def _get_raw_packet_representation(self, raw_packet: bytes) -> str:
		representation = ''
		
		if len(raw_packet) > self.MAX_VISIBLE_RAW_PACKET_SIZE:
			start = self._bytes_to_string(raw_packet[:int(self.MAX_VISIBLE_RAW_PACKET_SIZE / 2)])
			end = self._bytes_to_string(raw_packet[(-1) * int(self.MAX_VISIBLE_RAW_PACKET_SIZE / 2):])
			
			representation = start + '...' + end
		else:
			representation = self._bytes_to_string(raw_packet)
		
		return "'" + representation + "'"
	
	# We don't want to use bytes.decode() instead because the payload
	# is not necessarily human readable content
	def _bytes_to_string(self, bytes_representation: bytes) -> str:
		# Remove byte prefix (b'...') including the single quotes
		return str(bytes_representation)[2:-1]
		
	# Convert dict to a colored 'Key: Value' representation
	def create_colored_key_values_string(self, key_values: dict) -> None:
		message = ''
		
		for key, value in key_values.items():
			message += self.color('{0}: '.format(key), text_color='LIGHT_MAGENTA')
			message += self.color(str(value), text_color='LIGHT_BLUE')
			message += '  '
		
		return message.rstrip()
	
	"""
	Events for both the server and client
	"""
	def base_event_on_packet_received(self, client_id: Optional[int], session_id: int, remote_addr_pair: tuple, raw_packet: bytes, packet_type: int, packet_number: int, packet_keyword: int, payload_words: list) -> None:
		super().base_event_on_packet_received(client_id, session_id, remote_addr_pair, raw_packet, packet_type, packet_number, packet_keyword, payload_words)
		
		if packet_type in self.SUPPRESS_LIST_PACKET_TYPES:
			return
		
		# Raw packet size
		raw_packet_size = len(raw_packet)
		
		# Amount of payload byte words
		amount_of_byte_words = len(payload_words)
		
		log_data = {
			self.get_packet_name_by_type(packet_type): self._get_default_int_repr(packet_type),
			'Session ID': self._get_session_id_repr(session_id),
			'Client ID': self._get_default_int_repr(client_id),
			'Packet Size': raw_packet_size,
			'Number': self._get_packet_number_repr(packet_number),
			'Keyword': packet_keyword
		}
		
		if amount_of_byte_words == 0:
			log_data['Raw Packet ({0} Bytes)'.format(raw_packet_size)] = self._get_raw_packet_representation(raw_packet)
		else:
			log_data['Payload ({0} Words)'.format(amount_of_byte_words)] = self._get_payload_representation(payload_words)
		
		self.log(self.LOG_NAME_RECV_UNRELIABLE, None, log_data)
		
		return		
	
	def base_event_on_packet_sent(self, client_id: Optional[int], session_id: int, remote_addr_pair: Optional[tuple], raw_packet: bytes, packet_type: int, packet_number: int, packet_keyword: int, payload_words: list) -> None:
		super().base_event_on_packet_sent(client_id, session_id, remote_addr_pair, raw_packet, packet_type, packet_number, packet_keyword, payload_words)
		
		if packet_type in self.SUPPRESS_LIST_PACKET_TYPES:
			return		
		
		# Raw packet size
		raw_packet_size = len(raw_packet)
		
		# Amount of payload byte words
		amount_of_byte_words = len(payload_words)
		
		log_data = {
			self.get_packet_name_by_type(packet_type): self._get_default_int_repr(packet_type),
			'Session ID': self._get_session_id_repr(session_id),
			'Client ID': self._get_default_int_repr(client_id),
			'Packet Size': raw_packet_size,
			'Number': self._get_packet_number_repr(packet_number),
			'Keyword': packet_keyword
		}
		
		if amount_of_byte_words == 0:
			log_data['Raw Packet ({0} Bytes)'.format(raw_packet_size)] = self._get_raw_packet_representation(raw_packet)
		else:
			log_data['Payload ({0} Words)'.format(amount_of_byte_words)] = self._get_payload_representation(payload_words)
		
		self.log(self.LOG_NAME_SEND, None, log_data)
		
		return
		
	def base_event_on_packet_dropped(self, error_message: str) -> None:
		super().base_event_on_packet_dropped(error_message)
		
		self.log(self.LOG_NAME_DROPPED, 'Packet dropped', {
			'Message': error_message
		})
		
		return
	
	"""
	Client-side events
	"""
	def base_client_event_on_request_session(self) -> None:
		super().base_client_event_on_request_session()
		
		self.log(self.LOG_NAME_INIT, 'REQUEST SESSION (1/3): Kindly ask server to respond with an encrypted session id.', {})
		return
		
	def base_client_event_on_session_establishing(self, session_id: int) -> None:
		super().base_client_event_on_session_establishing(session_id)

		self.log(self.LOG_NAME_INIT, 'SESSION ESTABLISHING (2/3): Received session id from server.', {
			'Session ID': self._get_session_id_repr(session_id)
		})

		return
	
	def base_client_event_on_session_destroyed(self, reason: int) -> None:
		super().base_client_event_on_session_destroyed(reason)
		
		self.log(self.LOG_NAME_QUIT, 'Session destroyed.', {
			'Reason': self.get_client_session_destroy_reason_name_by_number(reason, '')
		})
		
		return	
	
	def base_client_event_on_server_shutdown(self) -> None:
		super().base_client_event_on_server_shutdown()
		
		self.log(self.LOG_NAME_QUIT, 'Server announced shutdown.', {})
		
		return	
	
	"""
	Server-side events
	"""
	def base_server_event_on_session_request(self, client_id: int, session_id: int, client_ip: str, client_port: int) -> bool:
		super().base_server_event_on_session_request(client_id, session_id, client_ip, client_port)
		
		self.log(self.LOG_NAME_INIT, 'REQUEST SESSION (1/3): Client asked server to respond with an encrypted session id.', {
			'Session ID': self._get_session_id_repr(session_id),
			'Client ID': self._get_client_id_repr(client_id),
			'IP': client_ip,
			'Port': client_port
		})
		
		return True
		
	def base_server_event_on_session_established(self, client_id: int, session_id: int) -> None:
		super().base_server_event_on_session_established(client_id, session_id)
		
		self.log(self.LOG_NAME_INIT, 'SESSION ESTABLISHED (3/3): Client confirmed receipt of session id.', {
			'Session ID': self._get_session_id_repr(session_id),
			'Client ID': self._get_client_id_repr(client_id)
		})
		
		return
		
	def base_server_event_on_client_unregistered(self, reason: int, client_id: int, session_id: int, client_ip: str, client_port: int) -> None:
		super().base_server_event_on_client_unregistered(reason, client_id, session_id, client_ip, client_port)
		
		self.log(self.LOG_NAME_QUIT, 'Client unregistered.', {
			'Reason': self.get_client_unregister_reason_name_by_number(reason, ''),
			'Session ID': self._get_session_id_repr(session_id),
			'Client ID': self._get_client_id_repr(client_id),
			'IP': client_ip,
			'Port': client_port
		})
		
		return
		
	def base_server_event_on_shutdown(self) -> None:
		super().base_server_event_on_shutdown()
		
		self.log(self.LOG_NAME_QUIT, 'Server is shutting down.', {})
		
		return
		
	"""
	Events from NeutrinoReliable
	"""
	def reliable_event_on_packet_received(self, client_id: Optional[int], session_id: int, remote_addr_pair: tuple, packet_type: int, packet_number: int, packet_keyword: int, payload_words: list) -> None:
		super().reliable_event_on_packet_received(client_id, session_id, remote_addr_pair, packet_type, packet_number, packet_keyword, payload_words)
		
		if packet_type in self.SUPPRESS_LIST_PACKET_TYPES:
			return		
		
		# Raw packet size
		raw_packet_size = 0
		
		# Amount of payload byte words
		amount_of_byte_words = len(payload_words)
		
		# The actual client id or None for the server (converted to -1)
		endpoint_id = client_id or -1
		
		log_data = {
			self.get_packet_name_by_type(packet_type): self._get_default_int_repr(packet_type),
			'Session ID': self._get_session_id_repr(session_id),
			'Client ID': self._get_default_int_repr(client_id),
			'Packet Size': raw_packet_size,
			'Number': self._get_packet_number_repr(packet_number),
			'Keyword': packet_keyword
		}
		
		log_data['Payload ({0} Words)'.format(amount_of_byte_words)] = self._get_payload_representation(payload_words)
		log_data['Buffers'] = 'In: {0} / Out: {1}'.format(len(self.buffer_incoming[endpoint_id]['packets']), len(self.buffer_outgoing[endpoint_id]['packets']))
		
		self.log(self.LOG_NAME_RECV_RELIABLE, None, log_data)
		
		return	
		
	def reliable_event_on_packet_retransmission_requested(self, client_id: Optional[int], session_id: int, packet_numbers_for_retransmission: list) -> None:
		super().reliable_event_on_packet_retransmission_requested(client_id, session_id, packet_numbers_for_retransmission)
		
		packet_numbers = []
		
		for number in packet_numbers_for_retransmission:
			packet_numbers.append(self._get_packet_number_repr(number))
			
		packet_numbers = ','.join(packet_numbers)
		
		self.log(self.LOG_NAME_RETR, 'Retransmission of {0} packet(s) requested due to probable loss.'.format(len(packet_numbers_for_retransmission)), {
			'Packet Number(s)': packet_numbers,
			'Session ID': self._get_session_id_repr(session_id),
			'Client ID': self._get_client_id_repr(client_id)
		})
		
		return
		
	def reliable_event_on_packet_retransmitted(self, client_id: Optional[int], session_id: int, retransmitted_packet_type: int, retransmitted_packet_number: int) -> None:
		super().reliable_event_on_packet_retransmitted(client_id, session_id, retransmitted_packet_type, retransmitted_packet_number)
		
		self.log(self.LOG_NAME_RETR, 'Packet retransmitted due to probable loss.', {
			'Number': self._get_packet_number_repr(retransmitted_packet_number),
			'Type': self.get_packet_name_by_type(retransmitted_packet_type) + ' ({0})'.format(self._get_default_int_repr(retransmitted_packet_type)),
			'Session ID': self._get_session_id_repr(session_id),
			'Client ID': self._get_client_id_repr(client_id)
		})
		
		return
		
	def reliable_event_on_duplicate_packet_detected(self, client_id: Optional[int], session_id: int, received_packet_type: int, received_packet_number: int, expected_packet_number: Optional[int]) -> None:
		super().reliable_event_on_duplicate_packet_detected(client_id, session_id, received_packet_type, received_packet_number, expected_packet_number)
		
		self.log(self.LOG_NAME_DUPLICATE, 'Duplicate packet detected.', {
			'Duplicate Packet Number': self._get_packet_number_repr(received_packet_number) + ' ({0})'.format(self._get_default_int_repr(received_packet_type)),
			'Expected Packet Number': self._get_packet_number_repr(expected_packet_number),
			'Session ID': self._get_session_id_repr(session_id),
			'Client ID': self._get_client_id_repr(client_id)
		})
		
		return
