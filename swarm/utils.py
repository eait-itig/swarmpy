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

from functools import partial
from typing import Generic, TypeVar, Union
from datetime import datetime

"""
Utility classes.
"""

VT = TypeVar('VT')
class TimedValue(Generic[VT]):
	"""
	Represents a snapshot of a value at a particular point in time.
	"""
	def __init__(self, value : VT = None, time : Union[datetime, int] = None, src : dict =None):
		if isinstance(time, datetime):
			time = time.timestamp()
		if src:
			self.__value = src['value']
			self.__time = int(src['time'])
		else:
			self.__value = value
			self.__time = int(time)
	def __repr__(self):
		return 'TimedValue(' + repr(self.time) + ', ' + repr(self.__value) + ')'
	def __str__(self):
		return str(self.__value)
	@property
	def value(self) -> VT:
		return self.__value
	@property
	def time(self) -> datetime:
		return datetime.fromtimestamp(self.__time)
	@property
	def raw_time(self) -> int:
		return self.__time
	

def metaprop_ro(getter, key):
	return property(partial(getter, key))

def metaprop(getter, setter, key):
	return property(partial(getter, key), partial(setter, key))
