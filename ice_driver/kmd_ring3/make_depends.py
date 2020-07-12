#!/usr/bin/env python2
#
# NNP-I Linux Driver
# Copyright (c) 2017-2019, Intel Corporation.
#
# This program is free software; you can redistribute it and/or modify it
# under the terms and conditions of the GNU General Public License,
# version 2, as published by the Free Software Foundation.
#
# This program is distributed in the hope it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
# FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
# more details.
#

#	foreach : $(CC) $(CFLAGS) -MM $(NAME).c | sed "s@^[^ ]@$(OBJDIR)/&@" > $@

import sys
import subprocess

def main(argv):
	flags = []
	files = []
	state = 0
	objdir = argv[1]
	for arg in argv[2:]:
		if state == 0:
			if arg == '--':
				state = 1
			else:
				flags.append(arg)
		else: # state == 1
			files.append(arg)
	print_deps(objdir, files, flags)

def print_deps(objdir, files, flags):
	for file in files:
		print_deps_single(objdir, file, flags)

def print_deps_single(objdir, filename, flags):
	if filename[-4:] == '.cpp':
		cc='g++'
	else:
		cc='gcc'
	cmd = [cc] + flags + ['-MM', filename]
	deps = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT).communicate()[0]
	print '%s/%s' % (objdir, deps)

if	__name__ == '__main__':
	main(sys.argv)
