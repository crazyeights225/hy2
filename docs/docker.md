## Running Hy2 with the pandare Docker Container

pandare (the Python interface to PANDA) can't be installed natively on Ubuntu versions after 20.04. To get around this, Hy2 can run the PANDA steps (**play** and **replay**) inside the official `pandare/panda` Docker container. Everything else (symbol resolution, building the model, checking properties, the web app) runs on the host as usual.

You run `miner.py` the same way as before. The orchestrators in `hy2/orch/` start the container for you.

### How it works

```
host                                     container (hy2-panda)
----                                     ---------------------
miner.py -a play / replay
  └─ hy2/orch/panda_play.py
     hy2/orch/panda_replay.py
        └─ hy2/orch/panda_docker.py ──── docker run ───► hy2/orch/container_entry.py
                                                           └─ runs PANDA (pandare)
        ◄──────── recording files / replay results ─────────┘
  └─ builds the CFG / model on the host
```

* The current directory, the Hy2 repository and the guest image's directory (for custom images) are mounted into the container **at the same paths**. This means relative paths in `config.json` and in the test case files still work.
* The container runs as your user, so recordings and other output files are owned by you, not root.
* Replay results are sent back to the host as a pickle file in `.hy2_docker/`. This file is deleted after it is loaded.
* Generic guest images downloaded by pandare are cached in `~/.cache/hy2-panda/.panda`, so they are only downloaded once.
* Pressing Ctrl-C stops the container.

### Requirements

* Docker
* The `pandare/panda` image: `docker pull pandare/panda`
* Hy2's Python dependencies on the host (see `docs/README.md`), ie.
  ```
  pip install rich transitions colorama capstone pyvex archinfo r2pipe z3-solver graphviz
  ```
  pandare does **not** need to be installed on the host.

### Setup

**1. Allow your user to run docker**

```
sudo usermod -aG docker $USER
```
Log out and back in, then check that `docker ps` works without sudo.

If you'd rather use sudo, set `"docker_cmd": "sudo docker"` in `config.json` (see below).

**2. Build the hy2-panda image**

The image extends `pandare/panda` with the tools the orchestrators need: `genisoimage` and the Python packages `colorama`, `capstone` and `transitions`. It is built automatically the first time it's needed, or you can build it yourself:
```
docker build -t hy2-panda docker/panda
```

To check it works:
```
docker run --rm hy2-panda python3 -c "import pandare, capstone, colorama, transitions; print('ok')"
```

**3. Configure `config.json` (optional)**

The defaults work for most setups. These options go in the `globals` section:

```json
{
    "globals": {
        ...
        "panda_backend": "auto",
        "docker_image": "hy2-panda",
        "docker_cmd": "docker",
        "docker_extra_args": []
    }
}
```

| Option | Default | Description |
|---|---|---|
| `panda_backend` | `auto` | `auto` uses docker when pandare can't be imported on the host. `docker` always uses the container. `native` never does. |
| `docker_image` | `hy2-panda` | The image to run. If it's `hy2-panda` and it doesn't exist, it is built from `docker/panda/Dockerfile`. |
| `docker_cmd` | `docker` | The command used to run docker, ie. `"sudo docker"`. |
| `docker_extra_args` | `[]` | Extra arguments passed to `docker run`, ie. `["-v", "/data:/data"]` to mount another directory. |

You can also override these with environment variables:
```
HY2_PANDA_BACKEND=docker HY2_DOCKER_CMD="sudo docker" python3 miner.py -c <test case> -a play
```

### Example: analyzing `add_two`

The `add_two` target runs on the generic x86_64 image that comes with pandare. Its test case is in `targets/add_two/`:

```json
{
  "target": "add_two",
  "recording_name": "sample",
  "arch": "x86_64",
  "image_type": "generic",
  "bin_type": "extern",
  "target_pages": "add_two",
  "preconditions": [""],
  "command": [{"cmd": "./add_two 1 2", "type": "sync"}]
}
```

Run all commands from the root of the repository.

**Record the execution (play):**
```
python3 miner.py -c targets/add_two/add_two_tc_97b6ef43218751e0f810c460cf43a7d2.json -a play
```

The first run downloads the generic Ubuntu 18.04 image (this takes a while). You should see output like:
```
[DOCKER] docker run --rm --init --name hy2-panda-... hy2-panda python3 -m hy2.orch.container_entry ...
using generic x86_64
...
writing snapshot:	./sample-rr-snp
recording started
Running ./add_two 1 2
Sum: 3
ending recording...
...complete!
run panda done!
play done....
```
This creates `sample-rr-snp` and `sample-rr-nondet.log` in the current directory.

**Replay and trace the recording:**
```
python3 miner.py -c targets/add_two/add_two_tc_97b6ef43218751e0f810c460cf43a7d2.json -a replay
```

PANDA replays the recording in the container, then the trace is analyzed on the host:
```
Replay completed successfully
done!
...
Building CFG
...
Building CFG-model
Done!
```
This writes `<test case>-backing.bin` and `<test case>-cfg.bin` to `targets/add_two/`.

**The remaining steps run on the host only** and are the same as without docker:
```
python3 miner.py -c add_two -a model
python3 miner.py -c add_two -a check
```
(`check` currently fails for `add_two`, see Known issues.)

> **Note:** Test case files must be named `<target>_tc_<name>.json` (ie. `add_two_tc_test1.json`). Replay fails with `ValueError: list.index(x): x not in list` otherwise.

### Using a custom guest image

For `"image_type": "custom"` the guest image is set in `config.json` with the keys the config loader reads, `guest_image` and `snapshot_name`:
```json
"guest_image": "/home/me/images/ubuntuserver.qcow2",
"snapshot_name": "srvd1"
```

The image's directory is mounted into the container automatically. The qcow2 is opened read/write, so the container must be able to write to it.

See the "Setting up an Image" section in `docs/installation.md` for how to prepare the image.

### Troubleshooting

**`permission denied while trying to connect to the docker API`**
Your user isn't in the `docker` group (see Setup step 1), or set `"docker_cmd": "sudo docker"`.

**`PANDA container exited with status N`**
The PANDA step failed inside the container. The error is printed above this line.

**A file outside the repository isn't found in the container**
Only the current directory, the repository and the guest image directory are mounted. Run from the repository root, or mount more directories with `docker_extra_args`.

**I want to run pandare natively**
Set `"panda_backend": "native"`. This is also the default behaviour of `auto` when pandare is installed on the host.

**Debugging inside the container**
Get a shell in the same environment the orchestrators use:
```
docker run --rm -it --user $(id -u):$(id -g) -v "$PWD:$PWD" -w "$PWD" \
    -e PYTHONPATH="$PWD" -e HOME=/hy2home -v ~/.cache/hy2-panda:/hy2home hy2-panda bash
```

### Known issues

* The replay of custom images uses the hardcoded snapshot name `srvd1` (`hy2/orch/panda_replay.py`) instead of `snapshot_name`.
* The default `config.json` sets the custom image with `x86_64_custom` and `x86_64_custom_snapshot`, but the loader reads `guest_image` and `snapshot_name`. Use the latter.
* `-a check` fails for `add_two` with `Exception: ERROR: var = None, SENSITIVE = None, ...` in `hy2/core/model.py`. This happens with or without docker.
* Only the generic image path has been tested with the container (`add_two`: play, replay and model).
