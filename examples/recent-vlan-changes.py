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
Search for all recent VLAN changes made to interfaces on a switch.
"""

import swarm
import argparse
import datetime

parser = argparse.ArgumentParser()
parser.add_argument('-u', '--uid', help='machine auth UID', required = True)
parser.add_argument('-k', '--key', help='machine auth secret key', required = True)
parser.add_argument('--since', type=datetime.datetime.fromisoformat, help='start time')
parser.add_argument('-v', '--vlan', type=int, help='vlan ID')
parser.add_argument('path', type=str, help='Path to examine')
args = parser.parse_args()

auth = swarm.MachAuthToken(uid=args.uid, key=args.key)
c = swarm.Client(auth)

containers = [c.container(args.path)]
while len(containers) > 0:
	cn = containers.pop(0)
	for s in cn.children:
		if isinstance(s, swarm.Container):
			containers.append(s)
		if not isinstance(s, swarm.Switch):
			continue
		if s.status.value in ('error', 'invalid'):
			continue
		print('# examining %s #' % s.path)

		for intf in s.interfaces:
			if args.since:
				h = intf.history_since(args.since)
			else:
				h = intf.history
			for c in h:
				if not isinstance(c, swarm.InterfaceChange):
					continue
				if args.since and c.time < args.since:
					continue
				if 'vlan' in c.changes:
					vlid = c.changes['vlan']
					if args.vlan and vlid != args.vlan:
						continue
					if intf.vlan and intf.vlan.value != vlid:
						continue
					matched = [v for v in s.vlans.value if v['id'] == vlid]
					if len(matched) < 1:
						continue
					print("%s\t%s\t%s\t%s\t%d" % (
					    s.path,
					    intf.name.value, intf.alias.value,
					    c.time, vlid))
