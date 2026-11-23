
# Documentation


## Warning:

This analysis will not work if not properly configured.

### Installation and Setup:

See `docs/installation.md`

On Ubuntu after 20.04, pandare can't be installed natively. Use the docker container instead, see `docs/docker.md`.

You will also need radare2 version 5.5.4, the newer version uses different commands, and a bunch of python packages.

![images/stop.png](images/stop.png) 

> Read the usage example in `usage.md` before continuing.


### Architecture and Project Organization:

### User Workflow:

### The Workload:

### Target Structure

### Web Application:

### Static Info:



### Target Configuration:

see `docs/configuration_options.md`

#### Test Cases:

Test cases describe how to exercise the program. They are typically in the form of a command. ie. for ls we may have a set of commands:
`ls`, `ls -lai`, `ls -w 1`, ...

We expect that the target program is executed once per test case.

### Addons and Extensions:

### Property Language:

`see docs/lang.md`

## Frontend:

To start frontend run:
```
flask run
```

The primary purpose of the frontend is to display results in a hopefully comphrensible way.
It can also be use to configure targets.

## Workflow:

![images/workflow.png](images/workflow.png)

After setting up testcases you need to follow the following workflow:
- play - for each test case
- replay - immediately following play for each test case
- model - after play, and replay for all test cases
- check - after model


```
./miner.py -c <config file name> -a <action>
```

For a single target you must:
- run play then replay for each test case
- run model
- run check

-----

### Project Org:

- bins
- docs
- hy2
    - core
    - orch
    - symres
- properties
    - dsl
    - json
- static
- targets
- templates

### Full List of Dependencies:

For pandare:
```
protobuf==3.6.1
```

radare2 version 5.5.4, the newer version uses different commands

```
- flask
- colorama
- pickle
- ctypes
- pytransitions
- r2pipe
- pygraphviz
- rich
- re
- pyvex
- pyclibrary
- capstone
- argparse
- hashlib
- asyncios
```
