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

import requests, json, re
import websocket

from cachetools import LRUCache
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry

from swarm.utils import *
from swarm.auth import *

from swarm.objects import Neighbour, MACNeighbour, CDPNeighbour
from swarm.objects import Interface, Switch, Container

from typing import Optional, List, Iterator, Tuple
try:
	from typing import TypedDict, Literal
except:
	from typing_extensions import TypedDict, Literal

class SystemStats(TypedDict):
	"""
	System stats about the swarm installation itself.
	"""
	uptime: str
	"""
	Uptime in the form `X days, Y hrs, Z mins and Q s`
	"""
	switches: float
	"""
	Total number of switches in the swarm instance.
	"""
	interfaces: float
	"""
	Total number of interfaces in the swarm instance.
	"""

class WriteProgress(object):
	"""
	An update on the progress of a write operation.
	"""
	def __init__(self, dic : dict):
		self.__dic = dic

	@property
	def finished(self) -> bool:
		"""
		Returns `True` if the write has finished and no further updates
		will be received.
		"""
		if self.__dic['empty'] == True:
			return True
		if self.__dic['type'] == 'reply':
			return True
		return False

	@property
	def progress(self) -> Tuple[int, int]:
		"""
		Returns the write operation's progress as tuple `(done, total)`.
		"""
		if self.__dic['progress'] is None:
			raise Exception('no progress information available')
		return (self.__dic['progress']['done'], self.__dic['progress']['size'])

	@property
	def percent(self) -> int:
		"""
		Returns the write operation's progress as a percentage.
		"""
		if self.finished:
			return 100
		(done, total) = self.progress
		return (100 * done) / total

class Client(object):
	"""
	The basic client object for interacting with the swarm API.
	"""
	def __init__(self, auth : MachAuthToken, endpoint : str = "swarm.netman.uq.edu.au"):
		self.auth = auth
		self.endpoint = endpoint
		self._ws = websocket.create_connection(
		    'wss://' + endpoint + '/api/ws',
		    origin='https://' + endpoint + '/api',
		    cookie='EAIT_WEB=' + self.auth.cookie)
		self._ws.ping()
		self._ws_cookie = 1
		self._writespecs = []
		self._sess = requests.Session()
		retries = Retry(total=5, backoff_factor=1,
		    status_forcelist=[ 502, 503, 504 ])
		self._sess.mount('https://', HTTPAdapter(max_retries = retries))
		self._cont_cache = LRUCache(maxsize = 50)
		self._sw_cache = LRUCache(maxsize = 20)
		self._intf_cache = LRUCache(maxsize = 100)

	def _get(self, path : str):
		cookies = {"EAIT_WEB": self.auth.cookie}
		return self._sess.get('https://' + self.endpoint + '/api' + path,
		    cookies = cookies)

	def _post(self, path : str, data : str, ctype : Optional[str] = None):
		cookies = {"EAIT_WEB" : self.auth.cookie}
		hdrs = {}
		if ctype:
			hdrs['Content-Type'] = ctype
		return self._sess.post(
		    'https://' + self.endpoint + '/api' + path,
		    cookies = cookies, data = data, headers = hdrs)

	def _delete(self, path):
		cookies = {"EAIT_WEB": self.auth.cookie}
		return self._sess.delete(
		    'https://' + self.endpoint + '/api' + path,
		    cookies = cookies)

	def _ws_request(self, method, args=[]):
		cookie = self._ws_cookie
		self._ws_cookie += 1
		req = json.dumps({
			'cookie': cookie,
			'method': method,
			'args': args
		})
		self._ws.send(req)
		while True:
			data = self._ws.recv()
			if data is None or data == "":
				continue
			reply = json.loads(data)
			if reply['cookie'] != cookie:
				raise Exception('Cookie mismatch')
			if reply['type'] == 'reply':
				if reply['status'] == 'error':
					if 'reason' in reply:
						raise Exception(reply['reason'])
					else:
						raise Exception(str(reply))
				if reply['status'] == 'ok':
					yield reply
					break
			if reply['type'] == 'partial_reply':
				yield reply

	def switch(self, path : str) -> Switch:
		"""
		Retrieves the `Switch` instance at a given path.
		"""
		if path not in self._sw_cache:
			self._sw_cache[path] = Switch(self, path)
		return self._sw_cache[path]

	def interface(self, path : str, index : int) -> Interface:
		"""
		Retrieves the `Interface` instance at a given path and interface
		index number.
		"""
		sw = self.switch(path)
		if (path,index) not in self._intf_cache:
			self._intf_cache[(path,index)] = Interface(self,
			    path, index, sw)
		return self._intf_cache[(path,index)]

	def container(self, path : str) -> Container:
		"""
		Retrieves the `Container` instance at a given path.
		"""
		if path not in self._cont_cache:
			self._cont_cache[path] = Container(self, path)
		return self._cont_cache[path]

	@property
	def root(self) -> Container:
		"""
		Retrieves the root container.
		"""
		return self.container("")

	@property
	def stats(self) -> SystemStats:
		"""
		Retrieves basic statistics about swarm's operating state.
		"""
		return next(self._ws_request('get_stats'))['data']

	@property
	def dirty(self) -> bool:
		"""
		Returns `True` if there are outstanding changes ready to be
		written by calling the `write()` method.
		"""
		return (len(self._writespecs) > 0)
	

	def write(self, commit : Optional[bool] = True) -> Iterator[WriteProgress]:
		"""
		Writes any queued changes to the switches, and performs a
		commit operation on each switch if `commit` is `True`.
		"""
		if len(self._writespecs) == 0:
			yield WriteProgress({"empty": True})
		else:
			args = [self._writespecs, commit]
			for x in self._ws_request('write', args):
				if x['type'] == 'reply' and x['status'] == 'ok':
					self._writespecs = []
				yield WriteProgress(x)

	def mac_search(self, mac_fragment : str) -> List[MACNeighbour]:
		"""
		Performs a MAC address search, returning `MACNeighbour`
		instances for each.
		"""
		r = self._get('/macs/' + mac_fragment)
		if r.status_code == 200:
			intfs = r.json()['interfaces']
			intfs.sort(key = lambda x: (x['path'], x['index']))
			neis = []
			for i in intfs:
				intf = self.interface(i['path'], i['index'])
				neis.append(MACNeighbour(intf, i['time'], i['mac']))
			return neis
		else:
			raise APIException(r.status_code, r.text)
