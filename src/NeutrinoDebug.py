#!/usr/bin/env python3
'''
Copyright (c) 2021–22 etkaar <https://github.com/etkaar/Neutrino>

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
Extension for easier debugging or logging purposes.
"""
class NeutrinoDebug:

	# Levels
	LOG_LEVEL_SUCCESS = 1
	LOG_LEVEL_WARNING = 2
	LOG_LEVEL_ERROR = 3
	
	LOG_LEVEL_INFO = 10
	LOG_LEVEL_TRAFFIC = 20

	# Names
	LOG_NAME_SEND = 1
	LOG_NAME_RECV = 2
	LOG_NAME_DROPPED = 3
	
	LOG_NAMES = {
		LOG_NAME_SEND: ' ► SEND ',
		LOG_NAME_RECV: ' RECV ◄ ',
		LOG_NAME_DROPPED: ' DROPPED ',
	}

	# Text and background colors
	TEXT_COLOR = {
		'BLACK': '\033[1;30m',
		'WHITE': '\033[1;37m',
		'BLUE': '\033[1;34m',
		'RED': '\033[1;31m',
		'LIGHT_RED': '\033[1;91m',
		'GREEN': '\033[1;32m',
		'ORANGE': '\033[1;33m',
		'GRAY': '\033[1;90m',
		'PURPLE': '\033[1;94m',
		'PINK': '\033[1;95m'
	}
	
	BG_COLOR = {
		'BLACK': '\033[40m',
		'WHITE': '\033[107m',
		'BLUE': '\033[44m',
		'RED': '\033[41m',
		'LIGHT_RED': '\033[101m',
		'GREEN': '\033[42m',
		'ORANGE': '\033[43m',
		'GRAY': '\033[100m',
		'PURPLE': '\033[104m',
		'PINK': '\033[105m'
	}
	
	RESET_COLOR = '\033[0m'

	# Empty to make inheritance easier
	def __init__(self):
		print("DEBUG")
		super().__init__()
	
	# Format message with color
	def color(self, message: str, text_color: str, bg_color: str, padding='', delimiter='') -> str:
		formatted = self.BG_COLOR[bg_color] + self.TEXT_COLOR[text_color] + padding + message + padding
		
		if delimiter is not '':
			formatted += self.BG_COLOR[bg_color] + self.TEXT_COLOR[text_color] + delimiter
		
		formatted += self.RESET_COLOR
		
		return formatted
		
	# Log
	def log(self, log_level: int, log_name: int, data: str) -> None:
		message = ''
		
		if log_level is self.LOG_LEVEL_TRAFFIC:
			message += self.BG_COLOR['PURPLE'] + self.TEXT_COLOR['WHITE'] + self.LOG_NAMES[log_name] + self.RESET_COLOR
			
		message += data
		
		print(message)
		
	# Create traffic log message
	def build_traffic_log_message(self, client_id: Optional[int], session_id: int, remote_addr_pair: Optional[tuple], raw_packet: bytes, packet_type: int, packet_number: int, packet_keyword: int, payload_words: list) -> None:
		# Session and client id
		session_id = self._get_int_repr(session_id)
		
		if client_id is not None:
			client_id = self._get_int_repr(client_id)
		else:
			client_id = 'None'
			
		# Raw packet size
		raw_packet_size = len(raw_packet)
		
		# Message
		message = self.color(self.get_packet_name_by_type(packet_type) + ' (' + self._get_int_repr(packet_type) + ')', 'WHITE', 'BLACK', ' ')
		message += self.color('SID: ' + session_id, 'WHITE', 'BLUE', ' ', '|')
		message += self.color('CID: ' + client_id, 'WHITE', 'BLUE', ' ', '|')
		message += self.color('SIZE: ' + str(raw_packet_size), 'WHITE', 'BLUE', ' ')
		message += self.color('NUMBER: ' + str(packet_number), 'WHITE', 'GREEN', ' ', '|')
		message += self.color('KEYWORD: ' + str(packet_keyword), 'WHITE', 'GREEN', ' ')
		message += self.color('PAYLOAD: ' + str(payload_words), 'WHITE', 'BLACK', ' ')
		
		return message
	
	"""
	OVERRIDINGS
	"""
	# Received any unencrypted packet
	def base_event_on_packet_received(self, client_id: Optional[int], session_id: int, remote_addr_pair: tuple, raw_packet: bytes, packet_type: int, packet_number: int, packet_keyword: int, payload_words: list) -> None:
		self.log(self.LOG_LEVEL_TRAFFIC, self.LOG_NAME_RECV, self.build_traffic_log_message(client_id, session_id, remote_addr_pair, raw_packet, packet_type, packet_number, packet_keyword, payload_words))
		return		
		
	# Sent any packet (encrypted or unprotected)
	def base_event_on_packet_sent(self, client_id: Optional[int], session_id: int, remote_addr_pair: Optional[tuple], raw_packet: bytes, packet_type: int, packet_number: int, packet_keyword: int, payload_words: list) -> None:
		self.log(self.LOG_LEVEL_TRAFFIC, self.LOG_NAME_SEND, self.build_traffic_log_message(client_id, session_id, remote_addr_pair, raw_packet, packet_type, packet_number, packet_keyword, payload_words))
		return
	
	# Packet was dropped
	def base_event_on_packet_dropped(self, error_message: str) -> None:
		self.log(self.LOG_LEVEL_TRAFFIC, self.LOG_NAME_DROPPED, str(error_message))
		return

