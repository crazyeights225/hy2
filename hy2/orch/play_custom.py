import time 
import os
import shutil
import sys
import subprocess
from colorama import Fore

def log_info(msg):
	print(Fore.YELLOW+f'[INFO] {msg}'+Fore.RESET)

def log_exit(msg):
	print(Fore.RED+f'[ERROR] {msg}'+Fore.RESET)

def create_iso(sample):
	#new_sample = "sample"
	#shutil.copy(sample, new_sample)
	
	# Create an ISO file of the sample file
	cmd = []
	cmd.append("/usr/bin/genisoimage")
	cmd.append("-iso-level")
	cmd.append("4")
	cmd.append("-l")
	cmd.append("-R")
	cmd.append("-J")
	cmd.append("-o")
	cmd.append("sample.iso")
	cmd.append(sample)    
	
	try:
		subprocess.check_call(cmd)
		log_info("Made an iso file for the sample")
	except Exception:
		#print(traceback.format_exc())
		print(sys.exc_info()[0])
		log_exit("Could not make any iso file for the sample")

def do_run_play(glob_config, recording_name, target_cmds, timeout, preconditions, postconditions, artifacts_dir, extern=False, record=True):
    from pandare import Panda  # imported here so the module can be loaded on hosts without pandare
    panda_flags = ["-show-cursor", "-display", 'none', "-loadvm", glob_config.snapshot_name, "-k", "en-us","-nographic"]
    panda = Panda(arch='x86_64', qcow=glob_config.guest_image, os="linux", mem="8192M", expect_prompt="ubuntu@ubuntu", extra_args=panda_flags)

    @panda.queue_blocking
    def drive_host():
        panda.revert_sync(glob_config.snapshot_name)
        time.sleep(10)
        if extern or "panda.mount bins" in preconditions:
            create_iso(artifacts_dir)
            panda.run_serial_cmd_async('id')
            print(panda.run_serial_cmd(''))
            panda.run_monitor_cmd('change ide1-cd0 sample.iso')
            time.sleep(5)
            panda.run_serial_cmd('echo "stdio sync"')
            
            panda.run_serial_cmd_async('sudo mount /dev/sr0 -o rw,X-mount.mkdir /media/mount')
            print(panda.serial_read_until("password for ubuntu:".encode()).decode())
            print(panda.run_serial_cmd('ubuntu'))
            print(panda.run_serial_cmd('ls /media/'))

            print(panda.run_serial_cmd('cd /media/mount/'))

        print("snapshot reverted")
        
        if len(preconditions) > 0:
            for cmd in preconditions:
                # TODO: FIXME
                if cmd == "panda.mount bins":
                    continue
                print(panda.run_serial_cmd(cmd, no_timeout=True))
        
        panda.run_monitor_cmd('begin_record '+recording_name)

        print('recording started')
        time.sleep(5)
        k = 15
        print(target_cmds)
        for cmd in target_cmds:
            if cmd['type'] == 'wait':
                time.sleep(cmd['cmd'])
            elif cmd["type"] == "async":
                print(f'Running {cmd["cmd"]}')
                print(panda.run_serial_cmd_async(cmd["cmd"], delay=k))
                if "until" in cmd:
                    print(panda.serial_read_until(cmd["until"].encode()).decode())
            else:
                print(f'Running {cmd["cmd"]}')
                print(panda.run_serial_cmd(cmd["cmd"], timeout=k))

            if k == 5:
                k = 1
        
        time.sleep(timeout)
        print("ending recording...")
        panda.run_monitor_cmd('end_record')
        print("Running postconditions")
        if len(postconditions) > 0:
            for cmd in postconditions:
                print(panda.run_serial_cmd(cmd, no_timeout=True))
        panda.end_analysis()

    print("Call drive host")
    print('run panda')
    panda.run()
    print("run panda done!")
    time.sleep(5)

