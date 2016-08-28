# lsop

`lsop` is a FreeBSD utility to list all processes running with outdated binaries or shared libraries (that is, binaries or shared libraries have been upgraded or simply deleted).

`lsop` does *not* currently work when started in a FreeBSD jail!


## Usage

Just run it. If everyting works as designed, utility will print all processes running with outdated binaries.

Exit codes are

  * `0` if no processes need restarting,
  * `1` on error of some sort,
  * `2` if one or more processes need restarting.


## Compilation

Just type `make`.


## Test

`Makefile` contains a simple "test suite". Type `make alltests` and it will execute four new `sleep` processess `lsop` should notify about.

For example:

    # make alltests
    mkdir -p test1/lib test1/libexec test1/bin
    ...
    mv -f test4/bin/sleep- test4/bin/sleep
    # ./lsop
    lsop: sysctl: kern.proc.pathname: 58187: No such file or directory
       pid    jid stat command
     58187      9 miss (sleep)
    lsop: sysctl: kern.proc.pathname: 58179: No such file or directory
     58179      9 miss (sleep)
     58170      9 miss .../lsop/test2/bin/sleep
     58162      9 miss .../lsop/test1/bin/sleep
