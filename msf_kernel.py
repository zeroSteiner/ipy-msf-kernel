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
import random
import re
import shlex
import signal
import string

import pexpect
import pexpect.replwrap
from ipykernel.kernelbase import Kernel
from ipykernel.kernelapp import IPKernelApp

__version__ = '0.1'

class MsfconsoleREPLWrapper(pexpect.replwrap.REPLWrapper):
	def __init__(self):
		self.child = pexpect.spawn(
			'./msfconsole',
			args=['--real-readline', '--quiet', '--execute-command', 'color true'],
			cwd=os.environ['MSF_HOME'],
			echo=False,
			maxread=5000
		)
		orig_prompt = re.escape('\x1b[0m> ')
		self._main_prompt_prefix = ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(16))
		prompt_change = "set Prompt {0}".format(self._main_prompt_prefix)
		new_prompt = re.escape(self._main_prompt_prefix) + '( [a-z]+\(.*\) )?' + re.escape('\x1b[0m> ')
		self.meterpreter_prompt = re.escape('\x1b[4mmeterpreter\x1b[0m > ')
		super(MsfconsoleREPLWrapper, self).__init__(
			self.child,
			orig_prompt,
			prompt_change,
			new_prompt
		)

	def _expect_prompt(self, timeout=-1):
		timeout = max(timeout, 10)
		self.child.expect([self.prompt, self.meterpreter_prompt], timeout=timeout)
		return 0

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
		self.timeout = 5
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

	@property
	def child(self):
		if self.msf_wrapper is None:
			return None
		return self.msf_wrapper.child

	def _setup_env(self):
		os.environ['GEM_HOME'] = os.path.expanduser('~/.rvm/gems/ruby-2.1.6')
		gem_paths = ('~/.rvm/gems/ruby-2.1.6', '~/.rvm/gems/ruby-2.1.6@global')
		os.environ['GEM_PATH'] = ':'.join([os.path.expanduser(p) for p in gem_paths])
		os.environ['MSF_HOME'] = os.path.expanduser('~/repos/msf')
		os.environ['RUBY_VERSION'] = 'ruby-2.1.6'

	def _start_msfconsole(self):
		sig = signal.signal(signal.SIGINT, signal.SIG_DFL)
		try:
			self.msf_wrapper = MsfconsoleREPLWrapper()
		finally:
			signal.signal(signal.SIGINT, sig)

	def _cmd_getpid(self, args, silent):
		return "PID = {0}\n".format(self.child.pid)

	def do_execute(self, code, silent, store_history=True, user_expressions=None, allow_stdin=False):
		if not code.strip():
			return {'status': 'ok', 'execution_count': self.execution_count, 'payload': [], 'user_expressions': {}}

		output = ''
		for cmd in code.split('\n'):
			cmd_out, interrupted = self.do_execute_command(cmd, silent)
			output += cmd_out
			if interrupted:
				break

		if not silent:
			stream_content = {'name': 'stdout', 'text': output}
			self.send_response(self.iopub_socket, 'stream', stream_content)

		if interrupted:
			return {'status': 'abort', 'execution_count': self.execution_count}

		return {'status': 'ok', 'execution_count': self.execution_count, 'payload': [], 'user_expressions': {}}

	def do_execute_command(self, cmd, silent):
		interrupted = False
		if cmd.startswith('%'):
			args = shlex.split(cmd)
			cmd = args.pop(0)[1:]
			if hasattr(self, '_cmd_' + cmd):
				return getattr(self, '_cmd_' + cmd)(args, silent), interrupted

		output = ''
		try:
			output = self.msf_wrapper.run_command(cmd, timeout=self.timeout)
		except KeyboardInterrupt:
			self.msf_wrapper.child.sendintr()
			interrupted = True
			self.msf_wrapper._expect_prompt()
			output = self.msf_wrapper.child.before
		except pexpect.EOF:
			output = self.msf_wrapper.child.before + 'Restarting Metasploit'
			self._start_msfconsole()
		return output, interrupted

if __name__ == '__main__':
	IPKernelApp.launch_instance(kernel_class=MetasploitKernel)
