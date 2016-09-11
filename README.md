# lsop

`lsop` is a FreeBSD utility to list all processes running with outdated binaries or shared libraries (that is, binaries or shared libraries have been upgraded or simply deleted).

`lsop` does *not* currently work when started in a FreeBSD jail!


## Usage

Just run it. If everyting works as designed, utility will print all processes running with outdated binaries.

If you experience false-positives (for example java processes might be wrongly accused as outdated) use `-c` and `-w` switches: `-c` will capture current system state in a whitelist file and later `-w` can be used to load this file and suppress warnings for those processes.

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


## How it works

`lsop` iterates over all running processes and looks through memory-mapped files with read + execute access; then it checks if those files are still available or have been modified/deleted.

Similar information might be acquired using `procstat -v <pid>` and `fstat -m -p <pid>`.

Since, at this time, kernel blanks file paths when file is deleted or replaced, `lsop` cannot distinguish between deleted or replaced file, as lacking path, it cannot check if a new version of file exists or not.
