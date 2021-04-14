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
Search for all interfaces in swarm on a particular VLAN.
"""

import swarm
import argparse

parser = argparse.ArgumentParser()
parser.add_argument('-u', '--uid', help='machine auth UID', required = True)
parser.add_argument('-k', '--key', help='machine auth secret key', required = True)
parser.add_argument('vlan', type=int, help='VLAN ID to search for')
args = parser.parse_args()

auth = swarm.MachAuthToken(uid=args.uid, key=args.key)
c = swarm.Client(auth)

containers = [c.root]
while len(containers) > 0:
	cn = containers.pop(0)
	for kid in cn.children:
		if isinstance(kid, swarm.Container):
			containers.append(kid)
		if not isinstance(kid, swarm.Switch):
			continue
		if kid.status.value in ('error', 'invalid'):
			continue
		matched = [v for v in kid.vlans.value if v['id'] == args.vlan]
		if len(matched) < 1:
			continue
		for i in kid.interfaces:
			if i.vlan and i.vlan.value == args.vlan:
				print("%s\t%s\t%s" % (kid.path,
				    i.name.value, i.alias.value))
	

