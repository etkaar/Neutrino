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
	pass		

"""
Client connects to server
"""
# Permanent Server Public Key: Shared with the clients.
server_public_key_hex = 'a923e0968a713987d76eba139c434ec3d85d7903f7605b02dcbf09996a6b535d'

# Create client endpoint
client_endpoint = Networking()
client_endpoint.init(host='127.0.0.1', port=22753, server=False)

client_endpoint.load_keys(None, None, server_public_key_hex)

try:
	while True:
		client_endpoint.request_frame()
except KeyboardInterrupt:
	client_endpoint.shutdown()
