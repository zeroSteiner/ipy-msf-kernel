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
import re
import shlex
import signal

import pexpect
import pexpect.replwrap
from ipykernel.kernelbase import Kernel
from ipykernel.kernelapp import IPKernelApp

__version__ = '0.1'

class MetasploitKernel(Kernel):
	implementation = 'msf_kernel'
	implementation_version = __version__
	language = 'metasploit'
	language_info = {
		'name': 'metasploit',
		'mimetype': 'text/plain',
		'file_extension': '.rc'
	}
	def __init__(self, *args, **kwargs):
		super(MetasploitKernel, self).__init__(*args, **kwargs)
		self._child = None
		self._setup_env()
		self._start_msfconsole()

	@property
	def language_version(self):
		version_output = self.msf_wrapper.run_command('version')
		match = re.search(r'Framework: (\d(\.\d{1,4}){2}(-\w+)?)', version_output)
		if match:
			return match.group(1)
		return ''

	@property
	def banner(self):
		return self.msf_wrapper.run_command('banner')

	def _setup_env(self):
		os.environ['GEM_HOME'] = os.path.expanduser('~/.rvm/gems/ruby-2.1.4@metasploit-framework')
		gem_paths = ('~/.rvm/gems/ruby-2.1.4@metasploit-framework', '~/.rvm/gems/ruby-2.1.4@global')
		os.environ['GEM_PATH'] = ':'.join([os.path.expanduser(p) for p in gem_paths])
		os.environ['MSF_HOME'] = os.path.expanduser('~/repos/msf')

	def _start_msfconsole(self):
		sig = signal.signal(signal.SIGINT, signal.SIG_DFL)
		try:
			self._child = pexpect.spawn(
				'./msfconsole -q',
				cwd=os.environ.get('MSF_HOME'),
				echo=False,
				maxread=5000
			)
			self.msf_wrapper = pexpect.replwrap.REPLWrapper(
				self._child,
				'\x1b[0m> ',
				None,
				'\x1b[0m> '
			)

		finally:
			signal.signal(signal.SIGINT, sig)

	def _cmd_getpid(self, args, silent):
		return "PID = {0}\n".format(self._child.pid)

	def do_execute(self, code, silent, store_history=True, user_expressions=None, allow_stdin=False):
		if not code.strip():
			return {'status': 'ok', 'execution_count': self.execution_count, 'payload': [], 'user_expressions': {}}

		output = ''
		code = code.rstrip()
		while code.startswith('%'):
			if '\n' in code:
				cmd, code = code.split('\n', 1)
			else:
				cmd = code
				code = ''
			args = shlex.split(cmd)
			cmd = args.pop(0)[1:]
			if hasattr(self, '_cmd_' + cmd):
				output += getattr(self, '_cmd_' + cmd)(args, silent)

		interrupted = False
		if code:
			try:
				output += self.msf_wrapper.run_command(code, timeout=None)
			except KeyboardInterrupt:
				self.msf_wrapper.child.sendintr()
				interrupted = True
				self.msf_wrapper._expect_prompt()
				output = self.msf_wrapper.child.before
			except pexpect.EOF:
				output = self.msf_wrapper.child.before + 'Restarting Metasploit'
				self._start_msfconsole()

		if not silent:
			# send standard output
			stream_content = {'name': 'stdout', 'text': output}
			self.send_response(self.iopub_socket, 'stream', stream_content)

		if interrupted:
			return {'status': 'abort', 'execution_count': self.execution_count}

		return {'status': 'ok', 'execution_count': self.execution_count, 'payload': [], 'user_expressions': {}}

if __name__ == '__main__':
	IPKernelApp.launch_instance(kernel_class=MetasploitKernel)
