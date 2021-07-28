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
Swarm API objects (switches, interfaces, containers etc)
"""

from __future__ import annotations

import requests, json, re

from swarm.utils import *

from datetime import datetime

from typing import Optional, Union, List, Tuple

try:
	from typing import TypedDict, Literal
except:
	from typing_extensions import TypedDict, Literal

class Neighbour(object):
	"""
	Represents a neighbour adjacency attached to a particular switch
	interface. Subclasses give identifying information about the neighbour
	itself.
	"""
	def __init__(self, client, path : str, index : int, stamp : int):
		self.__client = client
		self.__path = path
		self.__index = index
		self.__stamp = stamp

	def __repr__(self):
		return "Neighbour(" + self.__path + ", " + str(self.__index)  + ")"

	@property
	def switch(self) -> Switch:
		"""
		Switch which detected the neighbour.
		"""
		return self.__client.switch(self.__path)

	@property
	def interface(self) -> Interface:
		"""
		Interface on the switch where the neighbour was detected.
		"""
		return self.__client.interface(self.__path, self.__index)

	@property
	def time(self) -> datetime:
		"""
		Time at which the neighbour was last seen.
		"""
		return datetime.fromtimestamp(self.__stamp)
	@property
	def raw_time(self) -> int:
		"""
		Time at which the neighbour was last seen, as a raw number
		of seconds since the UNIX epoch.
		"""
		return self.__stamp

class MACNeighbour(Neighbour):
	"""
	A neighbour adjacency produced for each MAC address which has a
	forwarding entry on the given interface.
	"""
	def __init__(self, client, intf : Interface, stamp : int, mac : str):
		Neighbour.__init__(self, client, intf.path, intf.index, stamp)
		self.__mac = mac

	@property
	def mac(self) -> str:
		"""
		The neighbour's MAC address, in colon-separated hex format.
		"""
		return self.__mac

	def __repr__(self):
		return "MACNeighbour(" + self.path + ", " + \
			str(self.index) + ", " + self.__mac + ")"

class CDPNeighbour(Neighbour):
	"""
	A neighbour adjacency produced for each CDP neighbour which has been
	advertised on a given interface.
	"""
	def __init__(self, client, intf : Interface, stamp : int, rname : str, rintf : str):
		Neighbour.__init__(self, client, intf.path, intf.index, stamp)
		self.__rname = rname
		self.__rintf = rintf

	def __repr__(self):
		return "CDPNeighbour(" + self.__path + ", " + \
			str(self.__index) + ", " + repr(self.__rname) + ", " + \
			repr(self.__rintf) + ")"

	@property
	def remote_name(self) -> str:
		"""
		The CDP neighbour's advertised hostname
		"""
		return self.__rname

	@property
	def remote_interface(self) -> str:
		"""
		The CDP neighbour's advertised remote interface name
		"""
		return self.__rintf

class Change(object):
	"""
	Represents a change made to a switch or switch interface.
	"""
	def __init__(self, client: Client, path: str, blob: dict):
		self.__client = client
		self.__stamp = blob['time']
		self.__type = blob['type']
		self.__changes = blob['changes']
		self.__path = path

	@property
	def switch(self) -> Switch:
		"""
		The switch which had this change made to it (or recorded it).
		"""
		return self.__client.switch(self.__path)

	@property
	def changes(self) -> dict:
		"""
		The dictionary of attributes which changed.
		"""
		return self.__changes

	@property
	def time(self) -> datetime:
		"""
		Time at which the change was made or noticed.
		"""
		return datetime.fromtimestamp(self.__stamp)
	@property
	def raw_time(self) -> int:
		"""
		Time at which the change was made or noticed, as a raw number
		of seconds since the UNIX epoch.
		"""
		return self.__stamp

	@staticmethod
	def from_blob(client: Client, path: str, blob: dict):
		if blob['type'] == 'interface':
			return InterfaceChange(client, path, blob)
		elif blob['type'] == 'switch':
			return SwitchChange(client, path, blob)
		elif blob['type'] == 'interface_write':
			return InterfaceWriteChange(client, path, blob)
		elif blob['type'] == 'switch_write':
			return SwitchWriteChange(client, path, blob)
		else:
			raise Exception('Unsupported change type: ' +
			    blob['type'])

class InterfaceChange(Change):
	"""
	A change made to a switch interface which was detected by the poller
	(not made via swarm)
	"""
	def __init__(self, client, path, blob):
		Change.__init__(self, client, path, blob)
		self.__index = blob['index']

	@property
	def interface(self) -> Interface:
		"""The interface affected by this change."""
		return self.switch.interface(self.__index)


class InterfaceWriteChange(InterfaceChange):
	"""
	A change made to a switch interface via swarm.
	"""
	def __init__(self, client, path, blob):
		InterfaceChange.__init__(self, client, path, blob)
		self.__user = blob['user']

	@property
	def user(self) -> str:
		"""The username of the user who wrote this change."""
		return self.__user


class SwitchChange(Change):
	"""
	A change made to a switch (not one of its interfaces), detected by
	the poller (not made via swarm).
	"""
	def __init__(self, client, path, blob):
		Change.__init__(self, client, path, blob)

class SwitchWriteChange(SwitchChange):
	"""
	A change made to a switch (not one of its interfaces) via swarm.
	"""
	def __init__(self, client, path, blob):
		SwitchChange.__init__(self, client, path, blob)
		self.__user = blob['user']

	@property
	def user(self) -> str:
		"""The username of the user who wrote this change."""
		return self.__user

class Interface(object):
	"""
	An interface object in swarm, representing one specific interface on
	a network switch.
	"""
	def __init__(self, client, path : str, index : int, parent = None):
		self.__path = path
		self.__index = index
		self.__client = client
		self.__blob = None

	@property
	def path(self) -> str:
		"""
		The dot-separated path to this interface's owning switch in the
		swarm hierarchy.
		"""
		return self.__path

	@property
	def index(self) -> int:
		"""
		The SNMP index of this interface.
		"""
		return self.__index
	
	def __repr__(self):
		if self.__blob:
			return "Interface(" + self.__path + "/" + \
				str(self.__index)  + ": " + \
				self.__blob['data']['name'] + ")"
		else:
			return "Interface(" + self.__path + "/" + \
				str(self.__index) + ")"

	def _getblob(self):
		if self.__blob is None:
			r = self.__client._get('/interfaces/' + self.__path + \
			    "/" + str(self.__index))
			if r.status_code == 200:
				self.__blob = r.json()
			else:
				raise APIException(r.status_code, r.text)
		return self.__blob

	def _getprop(name, self):
		self._getblob()
		if name in self.__blob['data']:
			return TimedValue(src = self.__blob['data'][name])
		else:
			return None

	def _setprop(name, self, val):
		self.__client._writespecs.append({
			'path': self.__path,
			'attribute': name,
			'index': self.__index,
			'value': val
		})
		return val

	admin_status : TimedValue[str] = metaprop(_getprop, _setprop, "admin_status")
	"""
	The administrative status of this interface.
	"""
	oper_status : TimedValue[str] = metaprop_ro(_getprop, "oper_status")
	"""
	The operating status of this interface.
	"""

	alias : TimedValue[str] = metaprop(_getprop, _setprop, "alias")
	"""
	The "alias" of this interface (user-defined name, set with `description`
	in Cisco configuration).
	"""
	name : TimedValue[str] = metaprop_ro(_getprop, "name")
	"""
	The system's short name for this interface (e.g. `Gi0/1/0`).
	"""
	long_name : TimedValue[str] = metaprop_ro(_getprop, "description")
	"""
	The system's full name for this interface (e.g. `GigabitEthernet0/1/0`).
	"""
	
	speed : TimedValue[int] = metaprop_ro(_getprop, "speed")
	"""
	The operating speed of this interface in bits per second.
	"""
	trunk : TimedValue[bool] = metaprop_ro(_getprop, "trunk")
	"""
	Whether this interface is a "trunk" port (carries tagged VLANs).
	"""

	vlan : TimedValue[int] = metaprop(_getprop, _setprop, "vlan")
	"""
	The access VLAN of this interface.
	"""
	voice_vlan : TimedValue[int] = metaprop(_getprop, _setprop, "voice_vlan")
	"""
	The voice VLAN of this interface.
	"""

	@property
	def switch(self) -> Switch:
		"""
		The switch this interface belongs to.
		"""
		return self.__client.switch(self.__path)

	@property
	def neighbours(self) -> List[Neighbour]:
		"""
		Retrieves a list of all Neighbours visible on this interface.
		"""
		self._getblob()
		neis = []
		r = self.__client._get('/interfaces/' + self.__path + '/' + \
		    str(self.__index) + '/macs')
		if r.status_code == 200:
			for m in r.json()['macs']:
				neis.append(MACNeighbour(self.__client, self,
				    m['time'], m['mac']))
		else:
			raise APIException(r.status_code, r.text)
		for n in self.__blob['neighbours']:
			neis.append(CDPNeighbour(self.__client, self, n['time'],
			    n['remote_name'], n['remote_intf']))
		return neis

	@property
	def history(self) -> List[Change]:
		"""
		Retrieves a list of all changes that have affected this
		interface.
		"""
		changes = []
		r = self.__client._get('/interfaces/' + self.__path + '/' + \
		    str(self.__index) + '/history?interface_only=true')
		if r.status_code == 200:
			for m in r.json()['logs']:
				c = Change.from_blob(self.__client,
				    self.__path, m)
				changes.append(c)
		else:
			raise APIException(r.status_code, r.text)
		return changes

	def history_since(self, ts: datetime.datetime) -> List[Change]:
		"""
		Retrieves a list of all changes that have affected this
		interface after a particular timestamp.
		"""
		since = int(ts.timestamp())
		changes = []
		r = self.__client._get('/interfaces/' + self.__path + '/' + \
		    str(self.__index) + '/history?interface_only=true' +
		    '&since=' + str(since))
		if r.status_code == 200:
			logs = r.json()['logs']
			for m in r.json()['logs']:
				c = Change.from_blob(self.__client,
				    self.__path, m)
				changes.append(c)
		else:
			raise APIException(r.status_code, r.text)
		return changes


class Switch(object):
	"""
	A switch object in swarm, representing a network switch with
	interfaces.
	"""
	def __init__(self, client, path : str, new : bool = False):
		self.__path = path
		self.__client = client
		self.__intfs = {}
		self.__blob = None
		self.__new = new
		self.__changes = {}

	@property
	def path(self) -> str:
		"""
		The dot-separated path to this switch in the swarm hierarchy.
		"""
		return self.__path

	def __repr__(self):
		if self.__blob:
			return "Switch(" + self.__path + ": " + \
				self.__blob['config']['hostname'] + ")"
		return "Switch(" + self.__path + ")"

	def _getprop(name, self):
		if name in self.__changes:
			return TimedValue(value = self.__changes[name], time = 0)
		if self.__new:
			return None
		if self.__blob:
			return self.__blob['config'][name]
		r = self.__client._get('/switches/' + self.__path)
		if r.status_code == 200:
			self.__blob = r.json()
			return self.__blob['config'][name]
		else:
			raise APIException(r.status_code, r.text)

	def _getdataprop(name, self):
		if name in self.__changes:
			return TimedValue(value = self.__changes[name], time = 0)
		if self.__new:
			return None
		if self.__blob:
			return TimedValue(src = self.__blob['data'][name])
		r = self.__client._get('/switches/' + self.__path + '/data')
		if r.status_code == 200:
			self.__blob = r.json()
			return TimedValue(src = self.__blob['data'][name])
		else:
			raise APIException(r.status_code, r.text)

	def _setprop(name, self, val):
		self.__changes[name] = val
		return val

	def save(self) -> bool:
		"""
		Saves any outstanding changes made to this switch's
		configuration properties (`display_name`, `hostname`, etc).

		(To write data properties, see `write()` on the `Client`)
		"""
		path = self.__path
		if self.__new:
			if "hostname" not in self.__changes:
				raise Exception("New switches require at least a hostname")
			slug = self.__changes["hostname"].split(".")[0].lower()
			slug = re.sub(r"[^a-z0-9-_]+", "-", slug)
			path = self.__path + "." + slug
		r = self.__client._post('/switches/' + path, self.__changes)
		if r.status_code == 201 or r.status_code == 303:
			self.__blob = None
			self.__path = path
			self.__changes = {}
			self.__new = False
			return True
		elif r.status_code == 200:
			self.__blob = r.json()
			self.__path = path
			self.__changes = {}
			self.__new = False
			return True
		else:
			raise APIException(r.status_code, r.text)

	display_name : str = metaprop(_getprop, _setprop, "display_name")
	"""
	The friendly 'display name' for the container.
	"""
	ro_community : str = metaprop(_getprop, _setprop, "ro_community")
	"""
	The read-only SNMP community (if available).
	"""
	rw_community : str = metaprop(_getprop, _setprop, "rw_community")
	"""
	The read-write SNMP community (if available).
	"""
	hostname : str = metaprop(_getprop, _setprop, "hostname")
	"""
	The fully-qualified domain name of the switch (e.g.
	`01-0078-114-as01.netman.uq.edu.au`).
	"""
	acl : dict = metaprop(_getprop, _setprop, "acl")
	"""
	The access control list for this switch.
	"""

	description : TimedValue[str] = metaprop_ro(_getdataprop, "description")
	"""
	The SNMP 'system description' data for this switch (usually contains
	the output of `show version`).
	"""
	sysname : TimedValue[str] = metaprop_ro(_getdataprop, "sysname")
	"""
	The SNMP 'system name' data for this switch (the switch's own view
	of its fully-qualified domain name or hostname).
	"""
	stp_bridge_id : TimedValue[str] = metaprop_ro(_getdataprop, "stp_bridge_id")
	"""
	The switch's STP bridge ID.
	"""
	vlans : TimedValue[List[VLAN]] = metaprop_ro(_getdataprop, "vlans")
	"""
	Currenty configured VLANs available on this switch.
	"""
	uptime : TimedValue[int] = metaprop_ro(_getdataprop, "uptime")
	"""
	Uptime of the switch in seconds.
	"""

	@property
	def status(self) -> TimedValue[Literal['ok', 'error', 'invalid']]:
		"""
		Returns the current status of the switch's poller.
		"""
		if self.__new:
			return None
		r = self.__client._get('/switches/' + self.__path + '/status')
		if r.status_code == 200:
			st = r.json()['status']
			return TimedValue(src = st['status'])
		else:
			raise APIException(r.status_code, r.text)

	@property
	def progress(self) -> TimedValue[Tuple[int, int]]:
		"""
		Returns the current progress state of the switch's poller
		or writer as a tuple `(done, total)`.
		"""
		if self.__new:
			return None
		r = self.__client._get('/switches/' + self.__path + '/status')
		if r.status_code == 200:
			st = r.json()['status']
			v = (st['progress']['value']['done'], st['progress']['value']['size'])
			return TimedValue(value = v, time = st['progress']['time'])
		else:
			raise APIException(r.status_code, r.text)

	def delete(self):
		"""
		Deletes this switch.
		"""
		if self.__new:
			raise Exception("Cannot delete a switch that hasn't been created yet")
		r = self.__client._delete('/switches/' + self.__path)
		if r.status_code == 410 or r.status_code == 204:
			return True
		else:
			raise APIException(r.status_code, r.text)

	@property
	def interfaces(self) -> List[Interface]:
		"""
		Returns a list of all the switch's known interfaces.
		"""
		if self.__new:
			return []
		r = self.__client._get('/switches/' + self.__path + '/interfaces')
		if r.status_code == 200:
			intfs = r.json()['interfaces']
			return [self.__client.interface(self.__path, intf['index']) for intf in intfs]
		else:
			raise APIException(r.status_code, r.text)

	def interface(self, index : int) -> Interface:
		"""
		Retrives a specific interface by its index number.
		"""
		return self.__client.interface(self.__path, index)

	@property
	def history(self) -> List[Change]:
		"""
		Retrieves a list of all changes that have affected this
		switch.
		"""
		changes = []
		r = self.__client._get('/switches/' + self.__path + '/history')
		if r.status_code == 200:
			for m in r.json()['logs']:
				c = Change.from_blob(self.__client,
				    self.__path, m)
				changes.append(c)
		else:
			raise APIException(r.status_code, r.text)
		return changes

class VLAN(TypedDict):
	"""
	A configured VLAN on a switch.
	"""
	id: int
	name: str

class Container(object):
	"""
	A container object in swarm, which can contain other containers or
	switches.
	"""
	def __init__(self, client, path : str, new : bool = False):
		self.__path = path
		self.__client = client
		self.__blob = None
		self.__changes = {}
		self.__new = new

	@property
	def path(self) -> str:
		"""
		The dot-separated path to this container in the swarm hierarchy.
		"""
		return self.__path

	def __repr__(self):
		if self.__blob:
			return "Container(" + self.__path + ": " + \
				self.__blob['config']['display_name'] + ")"
		return "Container(" + self.__path + ")"

	def _getprop(name, self):
		if name in self.__changes:
			return self.__changes[name]
		if self.__blob:
			return self.__blob['config'][name]
		r = self.__client._get('/containers/' + self.__path)
		if r.status_code == 200:
			self.__blob = r.json()
			print(repr(self.__blob))
			return self.__blob['config'][name]
		else:
			raise APIException(r.status_code, r.text)

	def _setprop(name, self, val):
		self.__changes[name] = val
		return val

	def save(self) -> bool:
		"""
		Saves any outstanding changes made to this container's
		properties.
		"""
		path = self.__path
		if self.__new:
			if "display_name" not in self.__changes:
				raise Exception("New containers require at least a display_name")
			slug = self.__changes["display_name"].split(".")[0].lower()
			slug = re.sub(r"[^a-z0-9-_]+", "-", slug)
			path = self.__path + "." + slug
		r = self.__client._post('/containers/' + path, self.__changes)
		if r.status_code == 201 or r.status_code == 303:
			self.__blob = None
			self.__changes = {}
			self.__path = path
			return True
		elif r.status_code == 200:
			self.__blob = r.json()
			self.__changes = {}
			self.__path = path
			return True
		else:
			raise APIException(r.status_code, r.text)

	display_name : str = metaprop(_getprop, _setprop, "display_name")
	"""
	The friendly 'display name' for the container.
	"""
	ro_community : Optional[str] = metaprop(_getprop, _setprop, "ro_community")
	"""
	The read-only SNMP community (only visible to admins).
	"""
	rw_community : Optional[str] = metaprop(_getprop, _setprop, "rw_community")
	"""
	The read-write SNMP community (only visible to admins).
	"""
	acl : dict = metaprop(_getprop, _setprop, "acl")
	"""
	The access control list for this container and its children
	(only visible to admins)
	"""

	def new_switch(self) -> Switch:
		"""
		Creates a new child switch of this container and returns it.
		The new switch must have a `hostname` set and the `save()`
		method called before it is written into swarm.
		"""
		return Switch(new = True, path = self.__path, client = self.__client)

	def new_container(self) -> Container:
		"""
		Creates an empty new child container of this container and
		returns it. The new child container must have a `display_name`
		set and the `save()` method called before it is written
		into swarm.
		"""
		return Container(new = True, path = self.__path, client = self.__client)

	@property
	def children(self) -> List[Union[Container,Switch]]:
		"""
		Retrives all children (containers, switches) of this container.
		"""
		r = self.__client._get('/containers/' + self.__path + '/children')
		if r.status_code == 200:
			objs = []
			for jsobj in r.json()["children"]:
				if jsobj["type"] == "container":
					o = self.__client.container(jsobj["path"])
					objs.append(o)
				elif jsobj["type"] == "switch":
					o = self.__client.switch(jsobj["path"])
					objs.append(o)
			return objs
		else:
			raise APIException(r.status_code, r.text)

	def delete(self):
		"""
		Deletes this container.
		"""
		if len(self.__children) > 0:
			raise Exception('Cannot delete a container with children')
		r = self.__client._delete('/containers/' + self.__path)
		if r.status_code == 410:
			return True
		else:
			raise APIException(r.status_code, r.text)


