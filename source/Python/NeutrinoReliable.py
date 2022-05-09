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
from Neutrino import Neutrino

from typing import Optional

import exceptions.ExceptionsBase as ExBase
import exceptions.ExceptionsReliable as ExReliable

"""
An extended Neutrino class to introduce some
robustness and reliability.

Neutrino > NeutrinoReliable [> NeutrinoExtended]
"""
class NeutrinoReliable(Neutrino):
	"""
	CONSTANTS: COMMON
	"""
	# Add new packet type
	PACKET_TYPE_REQUEST_RETRANSMISSION: int = 0x21
	
	# Add packet type into packet types list
	PACKET_TYPES: list = Neutrino.PACKET_TYPES + [PACKET_TYPE_REQUEST_RETRANSMISSION]
	
	"""
	CONSTANTS: NETWORK
	"""
	# You need to increase this value if you're required to overcome long distances.
	# However, for fast connections within the same country or local networks, you
	# can choose a relatively small value of about 10 ms.
	#
	# NOTE: Bear in mind that this RTT does not only refer to the pure transmission
	# time within the network. If the opposite endpoint is slow, the RTT is going
	# to increase, so the total processing time is what counts.
	EXPECTED_AVERAGE_ROUND_TRIP_TIME: int = 10 # ms
	
	# Packets which are - after explicit request - not retransmitted within
	# this timeframe are requested again to be retransmitted. If that still
	# fails, it is attempted again while raising the timeout.
	FAST_RETRANSMISSION_TIMEOUT: int = EXPECTED_AVERAGE_ROUND_TRIP_TIME # ms
	SLOW_RETRANSMISSION_TIMEOUT: int = 100 # ms
	
	# Maximum amount of retransmission requests for a packet
	MAX_RETRANSMISSION_REQUESTS_PER_PACKET: int = 8
	
	# Max thread length of average RTT calculation
	# (e.g. 500 for average of the latest 500 packets)
	MAX_AVERAGE_RTT_RECORDING_THREAD_LENGTH: int = 500
	
	"""
	VARIABLES: NETWORK
	"""
	# Local recording of incoming and outgoing traffic, to allow packets to
	# be distributed in order and retransmitting of already sent packets.
	buffer_incoming: dict = {}
	buffer_outgoing: dict = {}
	
	# List of packets which are requested to be retransmitted
	requested_retransmission: dict = {}
	
	"""
	STATISTICS
	"""
	statistics: dict = {**Neutrino.statistics,
		# Number of unique packets requested for retransmission
		'unique_retransmission_requests': 0,
		
		# Total retransmission requests; thus also reattempts
		# if previous retransmission was not in time
		'total_retransmission_requests': 0,
		
		# Amount of dropped duplicate packets
		'dropped_duplicate_packets': 0,
		
		# Latest Round Trip Time (RTT)
		'latest_round_trip_time': 0,
		
		# Average RTT calculated by the latest n packets;
		# see MAX_AVERAGE_RTT_RECORDING_THREAD_LENGTH
		'average_round_trip_time': 0
	}
	
	average_round_trip_time_recording_sum: int = 0
	average_round_trip_time_recording_list: list = []
	
	"""
	DEBUG (Used for debugging purposes)
	"""
	induce_fake_loss: bool = False
	induce_double_spends: bool = False
	
	PACKET_TYPE_NAMES: dict = {**Neutrino.PACKET_TYPE_NAMES,
		PACKET_TYPE_REQUEST_RETRANSMISSION: 'REQUEST_RETRANSMISSION'
	}
	
	# Empty to make inheritance easier
	def __init__(self):
		super().__init__()
	
	"""
	EVENTS: Neutrino
	"""
	# Reset traffic buffers before session establishment
	def base_client_event_on_request_session(self) -> None:
		super().base_client_event_on_request_session()
		
		self.buffer_incoming = {}
		self.buffer_outgoing = {}
	
	# Delete traffic buffers for client
	def base_server_event_on_client_unregistered(self, reason: int, client_id: int, session_id: int, client_ip: str, client_port: int) -> None:
		super().base_server_event_on_client_unregistered(reason, client_id, session_id, client_ip, client_port)

		del self.buffer_incoming[client_id]
		
		# Can be undefined if server refused to answer to the client (see CLIENT_UNREGISTER_REASON_REFUSED)
		if client_id in self.buffer_outgoing:
			del self.buffer_outgoing[client_id]
	
	# Hook into Neutrino::base_event_on_register_any_packet() to handle PACKET_TYPE_REQUEST_RETRANSMISSION and PACKET_TYPE_KEEP_ALIVE
	def base_event_on_register_any_packet(self, client_id: Optional[int], session_id: int, remote_addr_pair: tuple, raw_packet: bytes, packet_type: int, packet_number: int, packet_keyword: int, payload_words: list) -> bool:		
		super().base_event_on_register_any_packet(client_id, session_id, remote_addr_pair, raw_packet, packet_type, packet_number, packet_keyword, payload_words)
		
		# Only if session is established
		if (self.is_server() is True and self.client_sessions[client_id]['session_state'] is self.INTERNAL_SESSION_STATE_ESTABLISHED) or (self.is_client() is True and self.is_session_to_server_established() is True):
			# The actual client id or None for the server (converted to -1)
			endpoint_id = client_id or -1
			
			# Opposite endpoint requests retransmission of possibly lost packet
			if packet_type is self.PACKET_TYPE_REQUEST_RETRANSMISSION:
				# Packet has exactly 1 word; extract packet number desired to be retransmitted
				try:
					(requested_packet_number,) = self._expect_n_words(payload_words, exactly=1)
				except ExBase.UnexpectedAmountOfWords:
					raise ExBase.NetworkError.InvalidPacket('Malformed REQUEST_RETRANSMISSION: Expected exactly one (1) word in payload.') from None
			
				# Convert bytes back to 64-bit integer
				requested_packet_number = self._int64_from_bytes(requested_packet_number)
				
				# Requested packet number cannot be or not longer be found in outgoing buffer
				if requested_packet_number not in self.buffer_outgoing[endpoint_id]['packets']:
					"""
					UNRECOVERABLE LOSS (OPPOSITE ENDPOINT) - Cannot fulfill request.
					
					Even if the session will timeout anyway because the opposite endpoint will give
					up after a certain amount of time, we do already here close the session.
					"""
					raise ExReliable.UnrecoverableLoss(client_id=client_id, session_id=session_id, message='Cannot fulfill opposite endpoints retransmission request for packet number <{0}>.'.format(requested_packet_number))
	
				# Retransmit packet 1:1
				(raw_packet, retransmitted_packet_type) = self.buffer_outgoing[endpoint_id]['packets'][requested_packet_number]
				self._write(remote_addr_pair, raw_packet)
				
				# Trigger event
				self.reliable_event_on_packet_retransmitted(client_id, session_id, retransmitted_packet_type, requested_packet_number)
				
				# Manually update clients session expire time since Neutrino::_register_[client|server]_packet() – where that happens – is blocked.
				if self.is_server() is True:
					self._update_clients_session_expire_time(client_id)
				# Do not forget to do that on client side
				elif self.is_client() is True:
					self._update_client_local_session_expire_time()
				
				# Block further processing of this packet in Neutrino::base_event_on_register_any_packet()
				return False
			
			# Opposite endpoint sends KEEP_ALIVE packet which contains its latest confirmed
			# packet number, which we need to clear our local outgoing buffer.
			elif packet_type is self.PACKET_TYPE_KEEP_ALIVE:
				# Packet has exactly 2 words; see self._send_keep_alive_packet()
				try:
					(time_sent_milliseconds, endpoints_latest_confirmed_packet_number) = self._expect_n_words(payload_words, exactly=2)
				except ExBase.UnexpectedAmountOfWords:
					raise ExBase.NetworkError.InvalidPacket('Malformed PACKET_TYPE_KEEP_ALIVE: Expected exactly two (2) words in payload.') from None
				
				# Convert bytes back to 64-bit integer
				endpoints_latest_confirmed_packet_number = self._int64_from_bytes(endpoints_latest_confirmed_packet_number)
				
				# Clear local outgoing buffer
				if endpoints_latest_confirmed_packet_number > self.buffer_outgoing[endpoint_id]['latest_confirmed_packet_number']:
					self._clear_outgoing_buffer(endpoint_id, endpoints_latest_confirmed_packet_number)
					self.buffer_outgoing[endpoint_id]['latest_confirmed_packet_number'] = endpoints_latest_confirmed_packet_number
				# Outdated value: Likely for retransmitted KEEP_ALIVE packets
				else:
					pass
					
				# KEEP_ALIVE packets are only initiated by clients, but the server will still respond to
				# each packet with another KEEP_ALIVE packet (which is not responded to then by the client).
				# While both parties transmit their unique 'latest_confirmed_packet_number', the server
				# leaves 'time_sent_milliseconds' as it is to allow the client a RTT measurement.
				if self.is_server() is True:
					self._send_keep_alive_packet(client_id=client_id, session_id=session_id, payload_words=[time_sent_milliseconds])
					
					# Manually update clients session expire time
					self._update_clients_session_expire_time(client_id)
					
					# Block further processing of this packet in Neutrino::base_event_on_register_any_packet()
					return False
				# So, that was our KEEP_ALIVE packet we previously sent to the server
				elif self.is_client() is True:
					# Update local session expire time
					self._update_client_local_session_expire_time()
				
					# Calculate Round Trip Time (RTT) from it. That is reliable, because packets are guaranteed
					# to be in order. Hence, e.g. if the KEEP_ALIVE was lost and then be retransmitted, of course
					# the RTT will increase; see also the explanation at EXPECTED_AVERAGE_ROUND_TRIP_TIME.
					round_trip_time = (self._get_current_time_milliseconds() - self._int64_from_bytes(time_sent_milliseconds))
					
					# Statistics: Set latest RTT, append latest RTT to recording list, update RTT recording list sum
					self.statistics['latest_round_trip_time'] = round_trip_time
					self.average_round_trip_time_recording_list.append(round_trip_time)
					self.average_round_trip_time_recording_sum += round_trip_time
					
					# Decrease total value by the oldest RTT value
					if len(self.average_round_trip_time_recording_list) > self.MAX_AVERAGE_RTT_RECORDING_THREAD_LENGTH:
						self.average_round_trip_time_recording_sum -= self.average_round_trip_time_recording_list.pop(0)
					
					# Calculate average RTT
					self.statistics['average_round_trip_time'] = round(self.average_round_trip_time_recording_sum / len(self.average_round_trip_time_recording_list))
			
		# Continue
		return True
	
	# Record any incoming packets to spot any loss and distribute these packets later in a reliable way
	def base_event_on_packet_received(self, client_id: Optional[int], session_id: int, remote_addr_pair: tuple, raw_packet: bytes, packet_type: int, received_packet_number: int, received_packet_keyword: int, payload_words: list) -> None:
		super().base_event_on_packet_received(client_id, session_id, remote_addr_pair, raw_packet, packet_type, received_packet_number, received_packet_keyword, payload_words)

		# The actual client id or None for the server (converted to -1)
		endpoint_id = client_id or -1
		
		if endpoint_id not in self.buffer_incoming:
			self.buffer_incoming[endpoint_id] = {
				'packets': {},
				'latest_confirmed_packet_number': self.PACKET_NUMBER_NONE,
				
				# The next expected packet number to ensure
				# packets are received in order.
				'next_packet_number': self.PACKET_NUMBER_NONE
			}
			
		if endpoint_id not in self.requested_retransmission:
			self.requested_retransmission[endpoint_id] = {}
		
		# The is the packet number where we know that itself and all packet numbers lower than it were
		# successfully received or retransmitted, so no uncompensated loss must be left behind.
		latest_confirmed_packet_number = self.buffer_incoming[endpoint_id]['latest_confirmed_packet_number']
		
		"""
		We cannot spot loss by observing the packet numbers, if no packet number
		is given yet due to pending authentication, so this takes place once
		the first time a packet is received containing a packet number.

		(In case loss takes place during the authentication, the session
		will timeout quickly, see Neutrino::SESSION_TIMEOUT_PENDING)
		"""
		if received_packet_number > self.PACKET_NUMBER_PENDING:
			"""
			This is the first time we receive a valid packet number within this session and
			so we need to initiate 'latest_confirmed_packet_number' with it. However, we need to
			make sure that this packet number comes from a hello packet (PACKET_TYPE_*_HELLO),
			otherwise non-recoverable loss has taken place within the authentication process.
			"""
			if latest_confirmed_packet_number < self.PACKET_NUMBER_PENDING:
				"""
				UNRECOVERABLE LOSS
				"""
				if packet_type not in [self.PACKET_TYPE_SERVER_HELLO2, self.PACKET_TYPE_CLIENT_HELLO3]:
					raise ExReliable.UnrecoverableLoss(client_id=client_id, session_id=session_id, message='Received unexpected packet type {0}. Either loss happened or packets were out of order during authentication.'.format(self._get_default_int_repr(packet_type)))
				
				# Initiate with very first received packet number
				self.buffer_incoming[endpoint_id]['latest_confirmed_packet_number'] = received_packet_number
				
				# We can safely distribute this packet
				self.buffer_incoming[endpoint_id]['next_packet_number'] = received_packet_number
			else:
				"""
				Now we ensure packets are received in order and not more than once.
				"""
				expected_packet_number = (latest_confirmed_packet_number + 1)
				
				# OK: In order, so no packet loss
				if received_packet_number == expected_packet_number:
					self.buffer_incoming[endpoint_id]['latest_confirmed_packet_number'] = latest_confirmed_packet_number = received_packet_number
				
				# LOSS: Packet number is larger than expected. We can assume that there could be a loss.
				elif received_packet_number > expected_packet_number:
				
					# In view of the worst possible loss gap we need to find out which packet numbers are
					# really missing. Receiving a packet number which is too large, does not necessarily
					# mean we have an amount of packets lost equal to the packet number differences.
					worst_possible_loss_gap = (received_packet_number - latest_confirmed_packet_number)
					missing_packet_numbers = []
					
					highest_subsequent_confirmed_packet_number = latest_confirmed_packet_number
				
					for n in range(1, worst_possible_loss_gap):
						possibly_missing_packet_number = (latest_confirmed_packet_number + n)
						
						# Did we receive a packet with this packet number before?
						if possibly_missing_packet_number not in self.buffer_incoming[endpoint_id]['packets']:
							missing_packet_numbers.append(possibly_missing_packet_number)
						else:
							if (highest_subsequent_confirmed_packet_number + 1) == possibly_missing_packet_number:
								self.buffer_incoming[endpoint_id]['latest_confirmed_packet_number'] = highest_subsequent_confirmed_packet_number = possibly_missing_packet_number
					
					self.buffer_incoming[endpoint_id]['latest_confirmed_packet_number'] = latest_confirmed_packet_number = highest_subsequent_confirmed_packet_number
					
					# We have at least one missing packet
					if len(missing_packet_numbers) > 0:
						# Pass through all packet numbers which are listed as missing
						packet_numbers_for_retransmission = []
						
						for missing_packet_number in missing_packet_numbers:
							# Initiate if this particular packet was never requested for retransmission
							if missing_packet_number not in self.requested_retransmission[endpoint_id]:
								self.requested_retransmission[endpoint_id][missing_packet_number] = {'request_expire_time': 0, 'count': 0}
								
								# Statistics
								self.statistics['unique_retransmission_requests'] += 1
							
							# Make sure that missing packets are not again requested to be retransmitted
							# without waiting for success for a short period of time.
							if self.requested_retransmission[endpoint_id][missing_packet_number]['request_expire_time'] < self._get_current_time_milliseconds():
								# Increment number of retransmission requests
								self.requested_retransmission[endpoint_id][missing_packet_number]['count'] += 1
								
								# Statistics
								self.statistics['total_retransmission_requests'] += 1
								
								# Raise timeout if this will be the third attempt
								if self.requested_retransmission[endpoint_id][missing_packet_number]['count'] >= 3:
									self.requested_retransmission[endpoint_id][missing_packet_number]['request_expire_time'] = (self._get_current_time_milliseconds() + self.SLOW_RETRANSMISSION_TIMEOUT)
								else:
									self.requested_retransmission[endpoint_id][missing_packet_number]['request_expire_time'] = (self._get_current_time_milliseconds() + self.FAST_RETRANSMISSION_TIMEOUT)
								
								# Append to retransmission list
								packet_numbers_for_retransmission.append(missing_packet_number)
								
								"""
								UNRECOVERABLE LOSS
								
								In case a packet is never received even after multiple requests for
								a retransmission something went very wrong.
								"""
								if self.requested_retransmission[endpoint_id][missing_packet_number]['count'] > self.MAX_RETRANSMISSION_REQUESTS_PER_PACKET:
									raise ExReliable.UnrecoverableLoss(client_id=client_id, session_id=session_id, message='Giving up on packet number {0}: Maximum amount of retransmission requests exceeded (see MAX_RETRANSMISSION_REQUESTS_PER_PACKET).'.format(missing_packet_number))
						
						# Request retransmission for all still missing packets
						if len(packet_numbers_for_retransmission) > 0:
							self._request_retransmission(client_id, session_id, remote_addr_pair, packet_numbers_for_retransmission)
							
							# Trigger event
							self.reliable_event_on_packet_retransmission_requested(client_id, session_id, packet_numbers_for_retransmission)
				
				# OUTDATED DUPLICATE: This packet number is too small, therefore we assume it was already received before
				elif received_packet_number < expected_packet_number:
					# Statistics
					self.statistics['dropped_duplicate_packets'] += 1
				
					# Trigger event
					self.reliable_event_on_duplicate_packet_detected(client_id, session_id, packet_type, received_packet_number, expected_packet_number)
				
					# Abort, otherwise it is added to the buffer
					return
		
			# NEW DUPLICATE: This packet number is too small, therefore we assume it was already received before
			if received_packet_number in self.buffer_incoming[endpoint_id]['packets']:
				# Statistics
				self.statistics['dropped_duplicate_packets'] += 1
				
				# Trigger event
				self.reliable_event_on_duplicate_packet_detected(client_id, session_id, packet_type, received_packet_number, None)
				
				# Abort, otherwise it is added to the buffer
				return

			# We may not distribute the packet yet, e.g. if there was some loss
			# detected between, so we record it here for later distribution
			self.buffer_incoming[endpoint_id]['packets'].update(
				{received_packet_number: (session_id, remote_addr_pair, packet_type, received_packet_keyword, payload_words)}
			)
	
	# On every requested frame (after successfull reading or read timeout)
	def base_event_on_requested_frame(self, frame_number: int, milliseconds_between_frames: int) -> None:
		super().base_event_on_requested_frame(frame_number, milliseconds_between_frames)
		
		# Pass through all endpoints
		for endpoint_id in self.buffer_incoming:
			# Do all at once, because if there is not yet the right packet,
			# we would hold and re-check next time. If we not pass through all
			# packets in order but only one per frame, we would come behind.
			while True:
				# Packet in order which is not a duplicate received
				next_packet_number = self.buffer_incoming[endpoint_id]['next_packet_number']
				
				if next_packet_number in self.buffer_incoming[endpoint_id]['packets']:
					# Return packet from buffer
					(session_id, remote_addr_pair, packet_type, original_packet_keyword, payload_words) = self.buffer_incoming[endpoint_id]['packets'][next_packet_number]
					
					# Get client id by session id
					client_id = None
					
					if self.is_server() is True:
						client_id = self._get_client_id_by_session_id(session_id)
					
					# Trigger event
					self.reliable_event_on_packet_received(client_id, session_id, remote_addr_pair, packet_type, next_packet_number, original_packet_keyword, payload_words)
					
					# Increment packet number
					self.buffer_incoming[endpoint_id]['next_packet_number'] += 1
				else:
					# Clear incoming traffic buffer by removing all packets with packet numbers
					# smaller or equal to the latest confirmed packet number
					self._clear_incoming_buffer(endpoint_id, self.buffer_incoming[endpoint_id]['latest_confirmed_packet_number'])
				
					# Do nothing, we will re-check next time
					break
	
	# Add sent packets into outgoing buffer to allow later retransmission
	# if requested by the opposite endpoint
	def base_event_on_packet_sent(self, client_id: Optional[int], session_id: int, remote_addr_pair: Optional[tuple], raw_packet: bytes, packet_type: int, packet_number: int, packet_keyword: int, payload_words: list) -> None:
		super().base_event_on_packet_sent(client_id, session_id, remote_addr_pair, raw_packet, packet_type, packet_number, packet_keyword, payload_words)
		
		# The actual client id or None for the server (converted to -1)
		endpoint_id = client_id or -1
			
		if endpoint_id not in self.buffer_outgoing:
			self.buffer_outgoing[endpoint_id] = {
				'packets': {},
				'latest_confirmed_packet_number': self.PACKET_NUMBER_NONE
			}
		
		# Do only store packets which already have a packet number
		if packet_number > self.PACKET_NUMBER_PENDING:
			self.buffer_outgoing[endpoint_id]['packets'].update(
				{packet_number: (raw_packet, packet_type)}
			)
			
		return
		
	"""
	OVERRIDINGS / EXTENSIONS
	"""
	# Override to inject the latest confirmed packet numbers into the KEEP_ALIVE packets
	# in order to allow the other endpoint to clear its outgoing buffer.
	#
	# PAYLOAD
	#  1) Timestamp in milliseconds of the time this KEEP_ALIVE packet is sent
	#  2) Latest confirmed packet number for this endpoint
	def _send_keep_alive_packet(self, client_id: Optional[int], session_id: Optional[int], payload_words: list=[]) -> None:
		# The actual client id or None for the server (converted to -1)
		endpoint_id = client_id or -1
		
		# Append current timestamp in milliseconds, but only for clients, the server will just
		# send back the clients value; see self.base_event_on_register_any_packet()
		if self.is_client() is True:
			current_time_milliseconds = self._get_current_time_milliseconds()
			payload_words = payload_words + [self._int64_to_bytes(current_time_milliseconds)]
		
		# Append latest confirmed packet number
		latest_confirmed_packet_number = self.buffer_incoming[endpoint_id]['latest_confirmed_packet_number']
		payload_words = payload_words + [self._int64_to_bytes(latest_confirmed_packet_number)]
		
		# Call with given payload byte words
		super()._send_keep_alive_packet(client_id, session_id, payload_words)
	
	# Only overridden for debugging purposes
	def _write(self, remote_addr_pair: tuple, raw_packet: bytes) -> int:
		# Supress outgoing packets with a probability of n% to provoke loss detection
		if self.induce_fake_loss is True:
			if self._get_random_int(1, 20) == 1:
				return 0
				
		# Double-spend (send twice) packets with a probability of n%
		if self.induce_double_spends is True:
			if self._get_random_int(1, 20) == 1:
				# Self-invoking (self instead of super()) causes an additional probability of multiple duplicates
				self._write(remote_addr_pair, raw_packet)
			
		return super()._write(remote_addr_pair, raw_packet)
	
	"""
	INTERNAL
	"""
	# Clear incoming buffer
	def _clear_incoming_buffer(self, endpoint_id: int, latest_confirmed_packet_number: int) -> None:
		for packet_number in list(self.buffer_incoming[endpoint_id]['packets']):
			if packet_number <= latest_confirmed_packet_number:
				del self.buffer_incoming[endpoint_id]['packets'][packet_number]
	
	# Clear outgoing buffer
	def _clear_outgoing_buffer(self, endpoint_id: int, latest_confirmed_packet_number: int) -> None:
		for packet_number in list(self.buffer_outgoing[endpoint_id]['packets']):
			if packet_number <= latest_confirmed_packet_number:
				del self.buffer_outgoing[endpoint_id]['packets'][packet_number]
	
	# Request retransmission of one or multiple packets
	def _request_retransmission(self, client_id: Optional[int], session_id: int, remote_addr_pair: tuple, packet_numbers: list) -> None:
		for packet_number in packet_numbers:
			self._send_packet(client_id, session_id, remote_addr_pair, packet_type=self.PACKET_TYPE_REQUEST_RETRANSMISSION, packet_number=self.PACKET_NUMBER_NONE, packet_keyword=self.PACKET_KEYWORD_NONE, raw_payload_bytes=None, payload_words=[self._int64_to_bytes(packet_number)])
		
	"""
	NEW EVENTS
	
	Just inherit this class to use events:
	
		> from NeutrinoReliable import NeutrinoReliable
		> class Neutrino(NeutrinoReliable):
		>   def event_*() -> ?:
		>      pass
	"""
	# Received any unencrypted packet after authentication has taken place
	#
	# Unlike Neutrino::base_event_on_packet_received(), this event guarantees that
	#	- packets are received in order (loss check),
	#	- packets are never distributed more than once (duplicate check).
	def reliable_event_on_packet_received(self, client_id: Optional[int], session_id: int, remote_addr_pair: tuple, packet_type: int, packet_number: int, packet_keyword: int, payload_words: list) -> None:
		return
	
	# Retransmission of a packet was requested
	def reliable_event_on_packet_retransmission_requested(self, client_id: Optional[int], session_id: int, packet_numbers_for_retransmission: list) -> None:
		return
		
	# Packet was retransmitted due to retransmission request from opposite.
	def reliable_event_on_packet_retransmitted(self, client_id: Optional[int], session_id: int, retransmitted_packet_type: int, retransmitted_packet_number: int) -> None:
		return
		
	# Once a duplicate packet was detected (informational event)
	def reliable_event_on_duplicate_packet_detected(self, client_id: Optional[int], session_id: int, received_packet_type: int, received_packet_number: int, expected_packet_number: Optional[int]) -> None:
		return
