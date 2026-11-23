import hy2.orch.play_custom as play_custom
import hy2.orch.play_default as play_default
import hy2.orch.panda_docker as panda_docker

# IN:
#  - glob_config - Global configuration
#  - image_type - generic or custom -  where generic refers to the pre-configured images that come with pandare
#  - arch - architecture
#  - recording_name - we create a recording of the execution of the guest which we replay and analyze in the next step - the name of this recording (default: sample)
#  - target_cmds - commands to use to exercise the target
#  - sample - name of the target (unused)
#  - timeout - time to wait for the execution of the guest to finish before ending the recording
#  - preconditions - commands to execute before executing the target
#  - postconditions - commands to execute after executing the target
#  - artifacts_dir - location of artifacts needed to exercise the target (ie. images, scripts, etc.)
#  - extern - (unused)
def do_play(glob_config, image_type, arch, recording_name, target_cmds, sample, timeout, preconditions, postconditions, artifacts_dir, extern):
    if panda_docker.use_docker(glob_config):
        return do_play_docker(glob_config, image_type, arch, recording_name, target_cmds, sample, timeout, preconditions, postconditions, artifacts_dir, extern)
    if image_type == "generic":
        play_default.do_run_play(glob_config, arch, recording_name, target_cmds, timeout, preconditions, postconditions, artifacts_dir, extern)
    else:
        play_custom.do_run_play(glob_config, recording_name, target_cmds, timeout, preconditions, postconditions, artifacts_dir, extern)


# Runs do_play inside the pandare docker container (see panda_docker.py)
def do_play_docker(glob_config, image_type, arch, recording_name, target_cmds, sample, timeout, preconditions, postconditions, artifacts_dir, extern):
    job = {
        "action": "play",
        "config": panda_docker.config_to_dict(glob_config),
        "args": {
            "image_type": image_type, "arch": arch, "recording_name": recording_name,
            "target_cmds": target_cmds, "sample": sample, "timeout": timeout,
            "preconditions": preconditions, "postconditions": postconditions,
            "artifacts_dir": artifacts_dir, "extern": extern,
        },
    }
    extra = [artifacts_dir] + (panda_docker.guest_image_paths(glob_config) if image_type != "generic" else [])
    result_file = panda_docker.run_job(glob_config, job, extra)
    panda_docker.load_result(result_file)
