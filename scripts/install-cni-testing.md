# Testing `install-cni.sh`

Testing framework for generating the CNI spec file. 

## Executing tests - TL;DR

```bash
make -C scripts test
```

Output:

```
Testing install-cni.sh
Running test [testcase/testcase-basic.sh]: PASS
Running test [testcase/testcase-directpath.sh]: PASS
Running test [testcase/testcase-dualstack.sh]: PASS
Test execution log available in test.log
```

## Concept 

Tests execute the `install-cni.sh` script with given set of env values (test
config) and verifies if script runs successfully (exit code == 0) and the
generated CNI spec file.

### Test cases

Each test case is defined in a separate file in `testcase/testcase-<NAME>.sh`.
For writing a new testcase you can copy the template file
[testcase/tpl-testcase.sh](testcase/tpl-testcase.sh).

Each testcase need to implement the `verify()` function that returns `0` on
success or non-zero otherwise.

### Static test configs
Static test configs should be stored in the `testdata/` folder.

### External commands call dependencies

The script mocks all calls to external commands that are used to gather data or
execute script flow (ie. curl, route, iptables, inotify). The default set of
mocks returns code 0 and no output as defined in the
`init_default_syscall_mocks()` function of 
[test-install-cni.sh](test-install-cni.sh).

For each test case the relevant set of mocks should be configured in the
`before_test()` function. If given system function is called in multiple
contexts, you should verify the arguments list and adjust the response
accordingly.

### Filesystem dependencies

The `install-cni.sh` script assumes some paths and files to exist within
the filesystem.

The following resources are mounted for test execution to meet these requirements:

* `test.out` folder is mounted as `/host/etc/cni/net.d` and will contain all
  generated CNI spec files. The file name will match the testcase name.
* `testdata/token` is mounted as `/var/run/secrets/kubernetes.io/serviceaccount/token`
  and simulates service account token

**Note** There are other filesystem dependencies that are not supported yet, ie.
`/sys/class/net/$nic/mtu`.

### Test execution

Tests are executed in the same docker image that is used for a target script
execution. This ensures the environment (shell, commands) will be the same as
during the `install-cni.sh` script execution in target environment.

The drawback of this solution is the fact that it is a distroless image with a
limited set of available commands, and you need to take it into consideration
when writing testcase code (i.e. comparing with `diff` is not available).

The entrypoint for tests execution is [test-install-cni.sh](test-install-cni.sh).

### Debugging testcases

The generated CNI spec file will be stored in the `test.out` folder. The output
of `install-cni.sh` script will be written to the `test.log` file.