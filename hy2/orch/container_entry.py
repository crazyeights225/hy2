#--------------------------------------
# File: container_entry.py
#
# Purpose: Entry point run inside the pandare docker container by
#  hy2/orch/panda_docker.py. Runs the native (pandare) orchestrators.
#
# Usage: python3 -m hy2.orch.container_entry <job.json>
#--------------------------------------
import json
import os
import sys
from types import SimpleNamespace

os.environ["HY2_IN_CONTAINER"] = "1"

import hy2.orch.panda_docker as panda_docker


def run_play(job, glob_config):
    import hy2.orch.panda_play as panda_play
    a = job["args"]
    panda_play.do_play(glob_config, a["image_type"], a["arch"], a["recording_name"], a["target_cmds"], a["sample"],
                       a["timeout"], a["preconditions"], a["postconditions"], a["artifacts_dir"], a["extern"])
    panda_docker.save_result(job["result_file"], {"ok": True})


def run_replay(job, glob_config):
    import hy2.orch.panda_replay as panda_replay
    a = job["args"]
    panda_replay.do_run_replay(glob_config, a["recording_name"], a["target"], a["target_pages"], a["out_of_scope"],
                               a["image_type"], a["inclusions"], a["inclusions_named"], a["target_type"], a["arch"])
    capture = panda_replay.scrape_capture
    capture.vmem_stream.flush()
    panda_docker.save_result(job["result_file"], {
        "scrape_capture": capture,
        "latency": panda_replay.export_latency(),
    })


def main():
    with open(sys.argv[1], "r") as f:
        job = json.load(f)
    glob_config = SimpleNamespace(**job["config"])
    if job["action"] == "play":
        run_play(job, glob_config)
    elif job["action"] == "replay":
        run_replay(job, glob_config)
    else:
        raise ValueError(f'Unknown action: {job["action"]}')


if __name__ == "__main__":
    main()
