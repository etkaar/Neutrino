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
class NeutrinoException(Exception):
	""" Allows to catch all Neutrino related exceptions using 'except ex.NeutrinoException: [...]' """

class ConfigurationError(NeutrinoException):
	__module__ = Exception.__module__
	
class LogicError(NeutrinoException):
	__module__ = Exception.__module__
	
class WritingIsLocked(NeutrinoException):
	__module__ = Exception.__module__
	
class LimitExceededError(NeutrinoException):
	__module__ = Exception.__module__
	
class EncodingError(NeutrinoException):
	__module__ = Exception.__module__
	
class UnexpectedAmountOfWords(NeutrinoException):
	__module__ = Exception.__module__
	
class ServerSideError(NeutrinoException):
	class SessionError(NeutrinoException):
		__module__ = Exception.__module__
		
	class ClientNotFound(NeutrinoException):
		__module__ = Exception.__module__
		
class ClientSideError(NeutrinoException):
	class Draining(NeutrinoException):
		__module__ = Exception.__module__

class NetworkError(NeutrinoException):
	class InvalidPacket(NeutrinoException):
		__module__ = Exception.__module__
		
	class UnexpectedPacket(NeutrinoException):
		__module__ = Exception.__module__
		
	class NoActiveSession(NeutrinoException):
		__module__ = Exception.__module__
		
	class NoOpenSocket(NeutrinoException):
		__module__ = Exception.__module__

class CryptoError(NeutrinoException):
	class DecryptionFailed(NeutrinoException):
		__module__ = Exception.__module__
		
	class InvalidPublicOrSecretKey(NeutrinoException):
		__module__ = Exception.__module__
		
	class InvalidPublicKey(NeutrinoException):
		__module__ = Exception.__module__
	
