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
from typing import Optional

"""
Monitors the network traffic. Used for debugging/testing purposes.
"""
class Monitoring:

	monitoring_started: int = 0

	# Text and background colors
	TEXT_COLOR = {
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
	
	BG_COLOR = {
		'DEFAULT': '\033[49m',
		
		'LIGHT_RED': '\033[101m',
		'LIGHT_GREEN': '\033[102m',
		'LIGHT_BLUE': '\033[104m',
		'LIGHT_MAGENTA': '\033[105m',
		'LIGHT_CYAN': '\033[106m',
		
		'BLACK': '\033[40m',
		'WHITE': '\033[107m'
	}
	
	RESET_COLOR = '\033[0m'

	# Names
	LOG_NAME_INIT = 1
	LOG_NAME_STATUS = 2
	LOG_NAME_SEND = 3
	LOG_NAME_RECV = 4
	LOG_NAME_DROPPED = 5
	LOG_NAME_QUIT = 6
	LOG_NAME_RETR = 7
	LOG_NAME_DUPLICATE = 8
	
	LOG_NAMES = {
		LOG_NAME_INIT: ['  INIT  ', BG_COLOR['LIGHT_CYAN'], TEXT_COLOR['BLACK']],
		LOG_NAME_STATUS: [' STATUS ', BG_COLOR['LIGHT_CYAN'], TEXT_COLOR['BLACK']],
		LOG_NAME_SEND: [' ► SEND ', BG_COLOR['LIGHT_BLUE'], TEXT_COLOR['WHITE']],
		LOG_NAME_RECV: [' ◄ RECV ', BG_COLOR['LIGHT_MAGENTA'], TEXT_COLOR['BLACK']],
		LOG_NAME_DROPPED: [' ❌DROP ', BG_COLOR['LIGHT_RED'], TEXT_COLOR['WHITE']],
		LOG_NAME_QUIT:[' ❌EXIT ', BG_COLOR['LIGHT_RED'], TEXT_COLOR['WHITE']],
		LOG_NAME_RETR:['  RETR  ', BG_COLOR['LIGHT_RED'], TEXT_COLOR['WHITE']],
		LOG_NAME_DUPLICATE:[' DUPLIC ', BG_COLOR['LIGHT_RED'], TEXT_COLOR['WHITE']]
	}
	
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
			if 'CID' in key_values:
				del key_values['CID']
		
		# Colored prefix
		message += self.LOG_NAMES[log_name][1] + self.LOG_NAMES[log_name][2] + self.LOG_NAMES[log_name][0] + self.RESET_COLOR + ' '
		
		# Time
		#message += self.color(self._add_leading_zeros(7, self._get_milliseconds_passed()), text_color='LIGHT_GRAY') + ' '
		message += self.color(str(self._get_current_time_milliseconds())[7:], text_color='LIGHT_GRAY') + ' '
		
		# Any status message (or nothing)
		if status_message is not None:
			message += self.color(status_message, text_color='LIGHT_CYAN')
			
			if key_values:
				message += ' – '
		
		# E.g. packet size and number, payload
		if key_values:
			message += self.create_colored_key_values_string(key_values)
		
		print(message)
		
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
		
		# Raw packet size
		raw_packet_size = len(raw_packet)
		
		self.log(self.LOG_NAME_RECV, None, {
			self.get_packet_name_by_type(packet_type): self._get_default_int_repr(packet_type),
			'SID': self._get_session_id_repr(session_id),
			'CID': self._get_default_int_repr(client_id),
			'Size': raw_packet_size,
			'Number': self._get_packet_number_repr(packet_number),
			'Keyword': packet_keyword,
			'Payload': payload_words
		})
		return		
	
	def base_event_on_packet_sent(self, client_id: Optional[int], session_id: int, remote_addr_pair: Optional[tuple], raw_packet: bytes, packet_type: int, packet_number: int, packet_keyword: int, payload_words: list) -> None:
		super().base_event_on_packet_sent(client_id, session_id, remote_addr_pair, raw_packet, packet_type, packet_number, packet_keyword, payload_words)
		
		# Raw packet size
		raw_packet_size = len(raw_packet)
		
		self.log(self.LOG_NAME_SEND, None, {
			self.get_packet_name_by_type(packet_type): self._get_default_int_repr(packet_type),
			'SID': self._get_session_id_repr(session_id),
			'CID': self._get_default_int_repr(client_id),
			'Size': raw_packet_size,
			'Number': self._get_packet_number_repr(packet_number),
			'Keyword': packet_keyword,
			'Payload': payload_words
		})
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
			'SID': self._get_session_id_repr(session_id)
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
			'SID': self._get_session_id_repr(session_id),
			'CID': self._get_client_id_repr(client_id),
			'IP': client_ip,
			'Port': client_port
		})	
		return True
		
	def base_server_event_on_session_established(self, client_id: int, session_id: int) -> None:
		super().base_server_event_on_session_established(client_id, session_id)
		
		self.log(self.LOG_NAME_INIT, 'SESSION ESTABLISHED (3/3): Client confirmed receipt of session id.', {
			'SID': self._get_session_id_repr(session_id),
			'CID': self._get_client_id_repr(client_id)
		})
		return
		
	def base_server_event_on_client_unregistered(self, reason: int, client_id: int, session_id: int, client_ip: str, client_port: int) -> None:
		super().base_server_event_on_client_unregistered(reason, client_id, session_id, client_ip, client_port)
		
		self.log(self.LOG_NAME_QUIT, 'Client unregistered.', {
			'Reason': self.get_client_unregister_reason_name_by_number(reason, ''),
			'SID': self._get_session_id_repr(session_id),
			'CID': self._get_client_id_repr(client_id),
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
	def reliable_event_on_packet_retransmission_requested(self, client_id: Optional[int], session_id: int, packet_numbers_for_retransmission: list) -> None:
		super().reliable_event_on_packet_retransmission_requested(client_id, session_id, packet_numbers_for_retransmission)
		
		packet_numbers = []
		
		for number in packet_numbers_for_retransmission:
			packet_numbers.append(self._get_packet_number_repr(number))
			
		packet_numbers = ','.join(packet_numbers)
		
		self.log(self.LOG_NAME_RETR, 'Retransmission of {0} packet(s) requested due to probable loss.'.format(len(packet_numbers_for_retransmission)), {
			'Packet Number(s)': packet_numbers,
			'SID': self._get_session_id_repr(session_id),
			'CID': self._get_client_id_repr(client_id)
		})
		return
		
	def reliable_event_on_packet_retransmitted(self, client_id: Optional[int], session_id: int, retransmitted_packet_type: int, retransmitted_packet_number: int) -> None:
		super().reliable_event_on_packet_retransmitted(client_id, session_id, retransmitted_packet_type, retransmitted_packet_number)
		
		self.log(self.LOG_NAME_RETR, 'Packet retransmitted due to probable loss.', {
			'Number': self._get_packet_number_repr(retransmitted_packet_number),
			'Type': self.get_packet_name_by_type(retransmitted_packet_type) + ' ({0})'.format(self._get_default_int_repr(retransmitted_packet_type)),
			'SID': self._get_session_id_repr(session_id),
			'CID': self._get_client_id_repr(client_id)
		})
		return
		
	def reliable_event_on_duplicate_packet_detected(self, client_id: Optional[int], session_id: int, received_packet_type: int, received_packet_number: int, expected_packet_number: Optional[int]) -> None:
		super().reliable_event_on_duplicate_packet_detected(client_id, session_id, received_packet_type, received_packet_number, expected_packet_number)
		
		self.log(self.LOG_NAME_DUPLICATE, 'Duplicate packet detected.', {
			'Duplicate Packet Number': self._get_packet_number_repr(received_packet_number) + ' ({0})'.format(self._get_default_int_repr(received_packet_type)),
			'Expected Packet Number': self._get_packet_number_repr(expected_packet_number),
			'SID': self._get_session_id_repr(session_id),
			'CID': self._get_client_id_repr(client_id)
		})
		return
