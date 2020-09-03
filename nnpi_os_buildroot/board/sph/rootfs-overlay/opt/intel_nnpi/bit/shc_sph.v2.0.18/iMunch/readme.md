% imunch User's Guide (Linux)

Synopsis
========

`imunch [-t int] [-c int] [-l int] [-q] [-h] [--version] [...]`

Description
===========

imunch is an Intel validation test tool to screen parts for undefined system behavior.

Installing `imunch`
-------------------

Ensure operating system fully supports installed processor and that [GLIBC] 2.7, or later, is installed.
Extract the .zip file containing imunch to a directory on the target system.

[GLIBC]: https://www.gnu.org/software/libc/

Using `imunch`
--------------

By default, imunch runs for 60 seconds and displays out to *stdout*:

    > ./imunch
    
    start:
      version: imunch x.y.z (Linux)
      arguments: ./imunch
      isaSupported: avx512skx
      osSupportsProcessor: true
      currentTime: Thu Nov 30 09:30:33 2017
    environment:
      isa: avx512skx
      coresDetected: 40
      coresToTest: 40
      processorsDetected: 40
      processorsToTest: 40
    test:
    summary:
      totalFailures: 0
      totalTests: 16111496746
      totalInputSets: 155391872
      averageTests: 402787418
      averageInputSets: 3884796
      minDeviationPercent: -1
      maxDeviationPercent: +0
      totalTime: 60.069
    exit: pass
    
    > echo $?
    
    0

Options
=======

General options
---------------

`-t` *INT*, `--timeInSeconds` *INT*

:   Specify *INTEGER* number of seconds to run, default is 60 seconds.

`-c` *INT*, `--core` *INT*

:   Restrict testing to specified logically-indexed physical core instead of all cores, default is not to restrict.

`-l` *INT*, `--limitMismatches` *INT*

:   Limit diagnostic information to first user-specified number of mismatches per thread per instruction, default is 1. Set to 0 to reduce tool output.

`-q`

:   If set, minimize diagnostic information displayed.

`-h`, `--help`

:   Display usage options.

`--version`

:   Display version number.

Advanced options (subject to change from release to release; not recommended for typical use)
---------------------------------------------------------------------------------------------

`--iterateCores`

:   Instead of testing all cores at once, test one core at a time with the same total run time

`--checksum`

:   Instead of regular test content, run specialized core-comparing checksum code to look for other kinds of undefined system behavior

`--verbose`

:   If set, and if `-q` is not specified, output additional diagnostic information.

`--listTests`

:   If set, print list of internal test names used for current processor and exit without testing.

`--ignoreOffline`

:   If set, and if any processors are offline, convert terminating error message into non-terminating warning.

`--forceExit` {`pass`, `abnormal`, `fail`, `unsupported`}

:   If set, force artificial early exit with specified exit type and status value.

`--processor` {`sse`, `avx2`, `avx512`}

:   If set, force maximum supported ISA under test to specified value.

`--limitISA`

:   If set, limit testing to maximum supported ISA.

Return codes
------------

`pass`

: No issues were found. Exit status value of 0.

`abnormal`

: The tool could not execute, likely due to incomplete operating system support or the arguments were not understood. Exit status value of 1.

`fail`

: One, or more, issues were found. See the *test* section for more information and return this part. Exit status value of 2.

`unsupported`

: The tool cannot work on this processor. Exit status value of 3.

*reboot* or *hang*

: Considered the same as `fail`, some part of the testing was unable to complete which would only happen if the installed processor is within the `fail` condition.

Error condition example
-----------------------

    > ./imunch
    
    start:
      version: imunch x.y.z (Linux)
      arguments: ./imunch
      isaSupported: avx512skx
      osSupportsProcessor: true
      currentTime: Thu Nov 30 09:48:26 2017
    environment:
      isa: avx512skx
      coresDetected: 28
      coresToTest: 28
      processorsDetected: 56
      processorsToTest: 56
    test:
    # Detected first failure in thread associated with core 25 (package 1) after 0.019 s <...>
    <...>
    summary:
      failingPackageIndices: [1]
      timeToFirstFailure: 0.017
      totalFailures: 268061
      <...>
    exit: fail
    
    > echo $?
    
    2

Author
======

Copyright 2017 Intel Corporation
