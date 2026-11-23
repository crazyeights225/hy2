#--------------------------------------
# File: panda_docker.py
#
# Purpose: Run the PANDA parts of the orchestrators (record/replay) inside the
#  pandare docker container, so the rest of hy2 can run on hosts where pandare
#  cannot be installed (ie. Ubuntu > 20.04).
#
#  The host-side orchestrator writes a JSON job file, starts the container with
#  the working directory (and anything else that is needed) bind-mounted at the
#  *same* absolute path, and the container runs hy2.orch.container_entry which
#  calls the native orchestrator. Replay results are pickled back to the host.
#
# Config (config.json -> globals):
#  - panda_backend: "auto" (default) | "docker" | "native"
#       auto -> use docker when pandare cannot be imported on the host
#  - docker_image: image to run (default: hy2-panda, built from docker/panda/Dockerfile)
#  - docker_cmd: command used to invoke docker, ie. "docker" or ["sudo", "docker"]
#  - docker_extra_args: extra arguments for `docker run` (list)
#
# Environment overrides: HY2_PANDA_BACKEND, HY2_DOCKER_IMAGE, HY2_DOCKER_CMD
#--------------------------------------
import importlib.util
import json
import os
import pickle
import shlex
import subprocess
import sys
import uuid

IN_CONTAINER_ENV = "HY2_IN_CONTAINER"
DEFAULT_IMAGE = "hy2-panda"

# Root of the repository (the directory that contains the hy2 package)
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DOCKERFILE_DIR = os.path.join(REPO_ROOT, "docker", "panda")
# Persistent HOME for the container, pandare caches the generic images in ~/.panda
CONTAINER_HOME = os.path.join(os.path.expanduser("~"), ".cache", "hy2-panda")
JOB_DIR = ".hy2_docker"


def _log(msg):
    print(f'[DOCKER] {msg}', flush=True)


def _cfg(glob_config, name, env, default):
    if env in os.environ and os.environ[env] != "":
        return os.environ[env]
    val = getattr(glob_config, name, None)
    return default if val in (None, "", []) else val


def use_docker(glob_config):
    if os.environ.get(IN_CONTAINER_ENV) == "1":
        return False
    backend = str(_cfg(glob_config, "panda_backend", "HY2_PANDA_BACKEND", "auto")).lower()
    if backend == "docker":
        return True
    if backend == "native":
        return False
    return importlib.util.find_spec("pandare") is None


def _docker_cmd(glob_config):
    cmd = _cfg(glob_config, "docker_cmd", "HY2_DOCKER_CMD", "docker")
    if isinstance(cmd, str):
        cmd = shlex.split(cmd)
    return list(cmd)


def _image(glob_config):
    return _cfg(glob_config, "docker_image", "HY2_DOCKER_IMAGE", DEFAULT_IMAGE)


def ensure_image(glob_config):
    docker = _docker_cmd(glob_config)
    image = _image(glob_config)
    try:
        res = subprocess.run(docker + ["image", "inspect", image], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
    except FileNotFoundError:
        raise RuntimeError(f'Could not run {docker[0]!r}, is docker installed? (docker_cmd in config.json)')
    if res.returncode == 0:
        return image

    err = res.stderr.strip()
    if "no such image" not in err.lower():
        # Not a missing image, docker itself is unreachable (ie. permission denied) - don't try to build
        raise RuntimeError(
            f'Cannot access docker: {err}\n'
            'If your user was recently added to the docker group, log out and back in '
            '(or run `newgrp docker` in this terminal). Alternatively set "docker_cmd": "sudo docker" in config.json.')
    if image != DEFAULT_IMAGE:
        # A user supplied image (ie. pandare/panda), let docker pull it on run
        return image
    _log(f'Image {image} not found, building it from {DOCKERFILE_DIR} ...')
    try:
        subprocess.check_call(docker + ["build", "-t", image, DOCKERFILE_DIR])
    except subprocess.CalledProcessError as e:
        raise RuntimeError(f'Building the {image} image failed (exit status {e.returncode}), see the docker output above.\n'
                           f'Build it manually to debug: {" ".join(docker)} build -t {image} {DOCKERFILE_DIR}')
    return image


def _mount_dirs(paths):
    # Bind-mount each directory at the same absolute path inside the container,
    # skipping directories already covered by another mount.
    dirs = []
    for p in paths:
        if not p:
            continue
        p = os.path.abspath(p)
        if not os.path.exists(p):
            continue
        if not os.path.isdir(p):
            p = os.path.dirname(p)
        dirs.append(os.path.realpath(p))
    dirs = sorted(set(dirs), key=len)
    mounts = []
    for d in dirs:
        if any(d == m or d.startswith(m.rstrip("/") + "/") for m in mounts):
            continue
        mounts.append(d)
    return mounts


def run_job(glob_config, job, extra_paths=()):
    """Run a job in the container. Returns the path to the job result file."""
    docker = _docker_cmd(glob_config)
    image = ensure_image(glob_config)

    cwd = os.getcwd()
    job_dir = os.path.join(cwd, JOB_DIR)
    os.makedirs(job_dir, exist_ok=True)
    job_id = uuid.uuid4().hex[:12]
    job_file = os.path.join(job_dir, f'{job_id}.json')
    result_file = os.path.join(job_dir, f'{job_id}.result')
    job = dict(job)
    job["result_file"] = result_file
    with open(job_file, "w") as f:
        json.dump(job, f)

    os.makedirs(CONTAINER_HOME, exist_ok=True)
    name = f'hy2-panda-{job_id}'
    args = docker + ["run", "--rm", "--init", "--name", name,
                     "-w", cwd,
                     "-e", f'{IN_CONTAINER_ENV}=1',
                     "-e", f'PYTHONPATH={REPO_ROOT}',
                     "-e", "PYTHONUNBUFFERED=1",
                     "-e", "HOME=/hy2home",
                     "-v", f'{CONTAINER_HOME}:/hy2home']
    if hasattr(os, "getuid"):
        # Keep files created in the mounted directories owned by the user
        args += ["--user", f'{os.getuid()}:{os.getgid()}']
    for d in _mount_dirs([cwd, REPO_ROOT] + list(extra_paths)):
        args += ["-v", f'{d}:{d}']
    extra = getattr(glob_config, "docker_extra_args", None) or []
    if isinstance(extra, str):
        extra = shlex.split(extra)
    args += list(extra)
    args += [image, "python3", "-m", "hy2.orch.container_entry", job_file]

    _log(' '.join(shlex.quote(a) for a in args))
    try:
        ret = subprocess.call(args)
    except KeyboardInterrupt:
        subprocess.call(docker + ["kill", name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        raise
    finally:
        try:
            os.remove(job_file)
        except OSError:
            pass
    if ret != 0:
        raise RuntimeError(f'PANDA container exited with status {ret}')
    return result_file


def config_to_dict(glob_config):
    # The parts of the global config the orchestrators use inside the container
    return {
        "guest_image": getattr(glob_config, "guest_image", ""),
        "snapshot_name": getattr(glob_config, "snapshot_name", ""),
        "target_space": getattr(glob_config, "target_space", ""),
    }


def guest_image_paths(glob_config):
    img = getattr(glob_config, "guest_image", "")
    return [img] if img else []


def load_result(result_file):
    try:
        with open(result_file, "rb") as f:
            return pickle.load(f)
    finally:
        try:
            os.remove(result_file)
        except OSError:
            pass


def save_result(result_file, data):
    with open(result_file, "wb") as f:
        pickle.dump(data, f)
