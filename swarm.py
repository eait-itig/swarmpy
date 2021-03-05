import requests, json, re
import base64, time, struct
import hmac, hashlib
import websocket
import random
import string
from functools import partial
from cachetools import LRUCache
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry

class MachAuthError(Exception):
	def __init__(self, code, text):
		self.text = text
		self.code = code
	def __str__(self):
		return repr(self.code) + ": " + repr(self.text)

class MachAuthToken(object):
	def __init__(self, uid, key, endpoint="swarm.netman.uq.edu.au"):
		self.uid = uid
		self.key = base64.b64decode(key)
		self.endpoint = endpoint
		self._cookie = None

	def get_cookie(self):
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
		r = requests.post('https://api.uqcloud.net/machauth', data = blob, headers = hdrs)
		if r.status_code == 200:
			reply = r.json()
			self._cookie = reply["cookie"]
			return self._cookie
		else:
			raise MachAuthError(r.status_code, r.text)

	cookie = property(get_cookie)

class Forbidden(Exception):
	def __init__(self):
		pass
	def __str__(self):
		return "Access denied to resource"

class APIException(Exception):
	def __init__(self, code, msg):
		self.code = code
		self.msg = msg
	def __str__(self):
		return repr(self.code) + ": " + repr(self.msg)

class TimedValue(object):
	def __init__(self, value=None, time=None, src=None):
		if src:
			self.value = src['value']
			self.time = int(src['time'])
		else:
			self.value = value
			self.time = int(time)
	def __repr__(self):
		return repr(self.value)
	def __str__(self):
		return str(self.value)

class Client(object):
	def __init__(self, auth, endpoint = "swarm.netman.uq.edu.au"):
		self.auth = auth
		self.endpoint = endpoint
		self._ws = websocket.create_connection('wss://' + endpoint + '/api/ws', origin='https://' + endpoint + '/api', cookie='EAIT_WEB=' + self.auth.cookie)
		self._ws.ping()
		self._ws_cookie = 1
		self._writespecs = []
		self._sess = requests.Session()
		retries = Retry(total=5, backoff_factor=1, status_forcelist=[ 502, 503, 504 ])
		self._sess.mount('https://', HTTPAdapter(max_retries = retries))
		self._cont_cache = LRUCache(maxsize = 50)
		self._sw_cache = LRUCache(maxsize = 20)
		self._intf_cache = LRUCache(maxsize = 100)

	def _get(self, path):
		cookies = {"EAIT_WEB": self.auth.cookie}
		return self._sess.get('https://' + self.endpoint + '/api' + path, cookies = cookies)

	def _post(self, path, data, ctype=None):
		cookies = {"EAIT_WEB" : self.auth.cookie}
		hdrs = {}
		if ctype:
			hdrs['Content-Type'] = ctype
		return self._sess.post('https://' + self.endpoint + '/api' + path, cookies = cookies, data = data, headers = hdrs)

	def _delete(self, path):
		cookies = {"EAIT_WEB": self.auth.cookie}
		return self._sess.delete('https://' + self.endpoint + '/api' + path, cookies = cookies)

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
					raise Exception(reply['reason'])
				if reply['status'] == 'ok':
					yield reply
					break
			if reply['type'] == 'partial_reply':
				yield reply

	def switch(self, path):
		if path not in self._sw_cache:
			self._sw_cache[path] = Switch(self, path)
		return self._sw_cache[path]

	def interface(self, path, index):
		sw = self.switch(path)
		if (path,index) not in self._intf_cache:
			self._intf_cache[(path,index)] = Interface(self, path, index, sw)
		return self._intf_cache[(path,index)]

	def container(self, path):
		if path not in self._cont_cache:
			self._cont_cache[path] = Container(self, path)
		return self._cont_cache[path]

	def root(self):
		return self.container("")

	def stats(self):
		return next(self._ws_request('get_stats'))['data']

	def write(self, commit=True):
		args = [self._writespecs, commit]
		for x in self._ws_request('write', args):
			if x['type'] == 'reply' and x['status'] == 'ok':
				self._writespecs = []
			yield x

	def mac_search(self, mac_fragment):
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


def metaprop_ro(getter, key):
	return property(partial(getter, key))
def metaprop(getter, setter, key):
	return property(partial(getter, key), partial(setter, key))

class Neighbour(object):
	def __init__(self, client, path, index, stamp, intf = None, sw = None):
		self.client = client
		self.path = path
		self.index = index
		self.stamp = stamp
		self.intf = intf

	def __repr__(self):
		return "Neighbour(" + self.path + "/" + str(self.index)  + ")"

	def switch(self):
		return self.client.switch(self.path)

	def interface(self):
		return self.client.interface(self.path, self.index)

	def time(self):
		return int(self.stamp)

	switch = property(switch)
	interface = property(interface)
	time = property(time)

class MACNeighbour(Neighbour):
	def __init__(self, intf, stamp, mac):
		Neighbour.__init__(self, intf.client, intf.path, intf.index, stamp, intf = intf, sw = intf.switch)
		self.mac = mac

	def __repr__(self):
		return "MACNeighbour(" + self.path + "/" + str(self.index) + ": " + self.mac + ")"

class CDPNeighbour(Neighbour):
	def __init__(self, intf, stamp, rname, rintf):
		Neighbour.__init__(self, intf.client, intf.path, intf.index, stamp, intf = intf, sw = intf.switch)
		self.rname = rname
		self.rintf = rintf

	def __repr__(self):
		return "CDPNeighbour(" + self.path + "/" + str(self.index) + ": " + self.rname + "/" + self.rintf + ")"

	def remote_name(self):
		return self.rname
	def remote_interface(self):
		return self.rintf
	remote_name = property(remote_name)
	remote_interface = property(remote_interface)

class Interface(object):
	def __init__(self, client, path, index, parent = None):
		self.path = path
		self.index = index
		self.client = client
		self.blob = None

	def __repr__(self):
		if self.blob:
			return "Interface(" + self.path + "/" + str(self.index)  + ": " + self.blob['data']['name'] + ")"
		else:
			return "Interface(" + self.path + "/" + str(self.index) + ")"

	def _getblob(self):
		if self.blob is None:
			r = self.client._get('/interfaces/' + self.path + "/" + str(self.index))
			if r.status_code == 200:
				self.blob = r.json()
			else:
				raise APIException(r.status_code, r.text)
		return self.blob

	def _getprop(name, self):
		self._getblob()
		if name in self.blob['data']:
			return TimedValue(src = self.blob['data'][name])
		else:
			return None

	def _setprop(name, self, val):
		self.client._writespecs.append({
			'path': self.path,
			'attribute': name,
			'index': self.index,
			'value': val
		})
		return val

	admin_status = metaprop(_getprop, _setprop, "admin_status")
	alias = metaprop(_getprop, _setprop, "alias")
	name = metaprop_ro(_getprop, "name")
	long_name = metaprop_ro(_getprop, "description")
	oper_status = metaprop_ro(_getprop, "oper_status")
	speed = metaprop_ro(_getprop, "speed")
	trunk = metaprop_ro(_getprop, "trunk")
	vlan = metaprop(_getprop, _setprop, "vlan")
	voice_vlan = metaprop(_getprop, _setprop, "voice_vlan")

	def switch(self):
		return self.client.switch(self.path)
	switch = property(switch)

	def save(self):
		g = self.client.write()
		x = next(g)
		for x in g:
			pass
		return x

	def neighbours(self):
		self._getblob()
		neis = []
		r = self.client._get('/interfaces/' + self.path + '/' + str(self.index) + '/macs')
		if r.status_code == 200:
			for m in r.json()['macs']:
				neis.append(MACNeighbour(self, m['time'], m['mac']))
		else:
			raise APIException(r.status_code, r.text)
		for n in self.blob['neighbours']:
			neis.append(CDPNeighbour(self, n['time'], n['remote_name'], n['remote_intf']))
		return neis
	neighbours = property(neighbours)

class Switch(object):
	def __init__(self, client, path, new = False):
		self.path = path
		self.client = client
		self.intfs = {}
		self.blob = None
		self.new = new
		self.changes = {}

	def __repr__(self):
		if self.blob:
			return "Switch(" + self.path + ": " + self.blob['config']['hostname'] + ")"
		return "Switch(" + self.path + ")"

	def _getprop(name, self):
		if name in self.changes:
			return TimedValue(value = self.changes[name], time = 0)
		if self.new:
			return None
		if self.blob:
			return self.blob['config'][name]
		r = self.client._get('/switches/' + self.path)
		if r.status_code == 200:
			self.blob = r.json()
			return self.blob['config'][name]
		else:
			raise APIException(r.status_code, r.text)

	def _getdataprop(name, self):
		if name in self.changes:
			return TimedValue(value = self.changes[name], time = 0)
		if self.new:
			return None
		if self.blob:
			return TimedValue(src = self.blob['data'][name])
		r = self.client._get('/switches/' + self.path)
		if r.status_code == 200:
			self.blob = r.json()
			return TimedValue(src = self.blob['data'][name])
		else:
			raise APIException(r.status_code, r.text)

	def _setprop(name, self, val):
		self.changes[name] = val
		return val

	def save(self):
		path = self.path
		if self.new:
			if "hostname" not in self.changes:
				raise Exception("New switches require at least a hostname")
			slug = self.changes["hostname"].split(".")[0].lower()
			slug = re.sub(r"[^a-z0-9-_]+", "-", slug)
			path = self.path + "." + slug
		r = self.client._post('/switches/' + path, self.changes)
		if r.status_code == 201 or r.status_code == 303:
			self.blob = None
			self.path = path
			self.changes = {}
			self.new = False
			return True
		elif r.status_code == 200:
			self.blob = r.json()
			self.path = path
			self.changes = {}
			self.new = False
			return True
		else:
			raise APIException(r.status_code, r.text)

	display_name = metaprop(_getprop, _setprop, "display_name")
	ro_community = metaprop(_getprop, _setprop, "ro_community")
	rw_community = metaprop(_getprop, _setprop, "rw_community")
	hostname = metaprop(_getprop, _setprop, "hostname")
	acl = metaprop(_getprop, _setprop, "acl")
	description = metaprop_ro(_getdataprop, "description")
	sysname = metaprop_ro(_getdataprop, "sysname")
	stp_bridge_id = metaprop_ro(_getdataprop, "stp_bridge_id")

	def status(self):
		if self.new:
			return None
		r = self.client._get('/switches/' + self.path + '/status')
		if r.status_code == 200:
			st = r.json()['status']
			return TimedValue(src = st['status'])
		else:
			raise APIException(r.status_code, r.text)

	def progress(self):
		if self.new:
			return None
		r = self.client._get('/switches/' + self.path + '/status')
		if r.status_code == 200:
			st = r.json()['status']
			v = (st['progress']['value']['done'], st['progress']['value']['size'])
			return TimedValue(value = v, time = st['progress']['time'])
		else:
			raise APIException(r.status_code, r.text)

	status = property(status)
	progress = property(progress)

	def delete(self):
		if self.new:
			raise Exception("Cannot delete a switch that hasn't been created yet")
		r = self.client._delete('/switches/' + self.path)
		if r.status_code == 410 or r.status_code == 204:
			return True
		else:
			raise APIException(r.status_code, r.text)

	def interfaces(self):
		if self.new:
			return []
		r = self.client._get('/switches/' + self.path + '/interfaces')
		if r.status_code == 200:
			intfs = r.json()['interfaces']
			return [self.client.interface(self.path, intf['index']) for intf in intfs]
		else:
			raise APIException(r.status_code, r.text)

	interfaces = property(interfaces)

	def interface(self, index):
		return self.client.interface(self.path, index)

class Container(object):
	def __init__(self, client, path, new = False):
		self.path = path
		self.client = client
		self.blob = None
		self.changes = {}
		self.new = new

	def __repr__(self):
		if self.blob:
			return "Container(" + self.path + ": " + self.blob['config']['display_name'] + ")"
		return "Container(" + self.path + ")"

	def _getprop(name, self):
		if name in self.changes:
			return self.changes[name]
		if self.blob:
			return self.blob['config'][name]
		r = self.client._get('/containers/' + self.path)
		if r.status_code == 200:
			self.blob = r.json()
			return self.blob['config'][name]
		else:
			raise APIException(r.status_code, r.text)

	def _setprop(name, self, val):
		self.changes[name] = val
		return val

	def save(self):
		path = self.path
		if self.new:
			if "display_name" not in self.changes:
				raise Exception("New containers require at least a display_name")
			slug = self.changes["display_name"].split(".")[0].lower()
			slug = re.sub(r"[^a-z0-9-_]+", "-", slug)
			path = self.path + "." + slug
		r = self.client._post('/containers/' + path, self.changes)
		if r.status_code == 201 or r.status_code == 303:
			self.blob = None
			self.changes = {}
			self.path = path
			return True
		elif r.status_code == 200:
			self.blob = r.json()
			self.changes = {}
			self.path = path
			return True
		else:
			raise APIException(r.status_code, r.text)

	display_name = metaprop(_getprop, _setprop, "display_name")
	ro_community = metaprop(_getprop, _setprop, "ro_community")
	rw_community = metaprop(_getprop, _setprop, "rw_community")
	acl = metaprop(_getprop, _setprop, "acl")

	def new_switch(self):
		return Switch(new = True, path = self.path, client = self.client)

	def new_container(self):
		return Container(new = True, path = self.path, client = self.client)

	def children(self):
		r = self.client._get('/containers/' + self.path + '/children')
		if r.status_code == 200:
			objs = []
			for jsobj in r.json()["children"]:
				if jsobj["type"] == "container":
					objs.append(self.client.container(jsobj["path"]))
				elif jsobj["type"] == "switch":
					objs.append(self.client.switch(jsobj["path"]))
			return objs
		else:
			raise APIException(r.status_code, r.text)

	children = property(children)
	def delete(self):
		r = self.client._delete('/containers/' + self.path)
		if r.status_code == 410:
			return True
		else:
			raise APIException(r.status_code, r.text)


