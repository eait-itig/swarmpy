#
# Copyright 2021 The University of Queensland
# Author: Alex Wilson <alex@uq.edu.au>
# 
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
# 
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
# IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
# OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
# IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
# NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
# THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
# 

"""
Authentication-related classes and exceptions.
"""

import requests, json
import base64, time, struct
import hmac, hashlib

from typing import Optional

class MachAuthError(Exception):
	"""
	An HTTP error which occurred during machine auth to api.uqcloud.net.
	"""
	def __init__(self, code : int, text : str):
		self.text = text
		"""
		The textual error message received.
		"""
		self.code = code
		"""
		The HTTP status code received.
		"""
	def __str__(self):
		return repr(self.code) + ": " + repr(self.text)

class MachAuthToken(object):
	"""
	A machine authentication token for use against uqcloud.net APIs.
	"""
	def __init__(self, uid : str, key : str, endpoint : Optional[str] = "swarm.netman.uq.edu.au"):
		"""
		`uid` and `key` must be obtained from api.uqcloud.net. `key` is
		base64-encoded.

		The `endpoint` argument must be set to the hostname of the
		final target API.
		"""
		self.uid = uid
		self.key = base64.b64decode(key)
		self.endpoint = endpoint
		self._cookie = None

	def get_cookie(self) -> str:
		"""
		Generates a session cookie for the machine auth user. This
		value should be provided in the `EAIT_WEB` cookie to the
		target API.
		"""
		if self._cookie:
			return self._cookie

		t = int(time.time())
		sigblob = struct.pack(">Q", t) + self.endpoint.encode('ascii')
		hm = hmac.new(self.key, sigblob, hashlib.sha256)
		sig = hm.digest()
		blob = json.dumps({
			'time': t,
			'target': self.endpoint,
			'user': self.uid,
			'signature': base64.b64encode(sig).decode('ascii'),
			'algorithm': 2 # hmac_sha256
		})
		hdrs = {'content-type': 'application/json'}
		r = requests.post('https://api.uqcloud.net/machauth',
		     data = blob, headers = hdrs)
		if r.status_code == 200:
			reply = r.json()
			self._cookie = reply["cookie"]
			return self._cookie
		else:
			raise MachAuthError(r.status_code, r.text)

	cookie = property(get_cookie)

class Forbidden(Exception):
	"""
	Exception produced when access was denied to a particular API resource.
	"""
	def __init__(self):
		pass
	def __str__(self):
		return "Access denied to resource"

class APIException(Exception):
	"""
	A generic HTTP API error.
	"""
	def __init__(self, code : int, msg : str):
		self.code = code
		"""
		The HTTP status code received.
		"""
		self.msg = msg
		"""
		The textual error message received.
		"""
	def __str__(self):
		return repr(self.code) + ": " + repr(self.msg)
