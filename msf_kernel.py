#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
#  msf_kernel.py
#
#  Copyright 2015 Spencer McIntyre <zeroSteiner@gmail.com>
#
#  Redistribution and use in source and binary forms, with or without
#  modification, are permitted provided that the following conditions are
#  met:
#
#  * Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
#  * Redistributions in binary form must reproduce the above
#    copyright notice, this list of conditions and the following disclaimer
#    in the documentation and/or other materials provided with the
#    distribution.
#  * Neither the name of the  nor the names of its
#    contributors may be used to endorse or promote products derived from
#    this software without specific prior written permission.
#
#  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
#  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
#  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
#  A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
#  OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
#  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
#  LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
#  DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
#  THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
#  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
#  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#

import os
import signal

import pexpect
import pexpect.replwrap
from IPython.kernel.zmq.kernelbase import Kernel
from IPython.kernel.zmq.kernelapp import IPKernelApp

__version__ = '0.1'

class MetasploitKernel(Kernel):
	_banner = None
	implementation = 'msf_kernel'
	implementation_version = __version__
	language = 'metasploit'
	language_info = {
		'name': 'metasploit',
		'mimetype': 'text/plain',
		'file_extension': '.rc'
	}
	@property
	def language_version(self):
		return __version__

	@property
	def banner(self):
		return self.msf_wrapper.run_command('banner')

	def __init__(self, *args, **kwargs):
		super(MetasploitKernel, self).__init__(*args, **kwargs)
		self._setup_env()
		self._start_msfconsole()

	def _setup_env(self):
		if 'GEM_HOME' in os.environ and not os.environ['GEM_HOME'].endswith('@metasploit-framework'):
			os.environ['GEM_HOME'] = os.environ['GEM_HOME'] + '@metasploit-framework'
		if 'GEM_PATH' in os.environ:
			gem_path_parts = os.environ['GEM_PATH'].split(os.pathsep)
			if not gem_path_parts[0].endswith('@metasploit-framework'):
				gem_path_parts[0] = gem_path_parts[0] + '@metasploit-framework'
				os.environ['GEM_PATH'] = ':'.join(gem_path_parts)

	def _start_msfconsole(self):
		sig = signal.signal(signal.SIGINT, signal.SIG_DFL)
		try:
			child = pexpect.spawn('./msfconsole', cwd=os.environ.get('MSF_HOME'), maxread=5000, echo=False)
			self.msf_wrapper = pexpect.replwrap.REPLWrapper(child, '\x1b[0m> ', None, new_prompt='\x1b[0m> ')
		finally:
			signal.signal(signal.SIGINT, sig)

	def do_execute(self, code, silent, store_history=True, user_expressions=None, allow_stdin=False):
		if not code.strip():
			return {'status': 'ok', 'execution_count': self.execution_count, 'payload': [], 'user_expressions': {}}

		interrupted = False
		try:
			output = self.msf_wrapper.run_command(code.rstrip(), timeout=None)
		except KeyboardInterrupt:
			self.msf_wrapper.child.sendintr()
			interrupted = True
			self.msf_wrapper._expect_prompt()
			output = self.msf_wrapper.child.before
		except pexpect.EOF:
			output = self.msf_wrapper.child.before + 'Restarting Metasploit'
			self._start_msfconsole()

		if not silent:
			# Send standard output
			stream_content = {'name': 'stdout', 'text': output}
			self.send_response(self.iopub_socket, 'stream', stream_content)

		if interrupted:
			return {'status': 'abort', 'execution_count': self.execution_count}

		return {'status': 'ok', 'execution_count': self.execution_count, 'payload': [], 'user_expressions': {}}

if __name__ == '__main__':
	IPKernelApp.launch_instance(kernel_class=MetasploitKernel)