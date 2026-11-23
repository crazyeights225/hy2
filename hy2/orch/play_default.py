import time
import os

def do_run_play(glob_config, arch, recording_name, target_cmds, timeout, preconditions, postconditions, artifacts_dir, extern=False, record=True):
    from pandare import Panda  # imported here so the module can be loaded on hosts without pandare
    panda = Panda(generic=arch, extra_args=["-nographic"])

    @panda.queue_blocking
    def drive_host():
        #panda.revert_sync('net4')
        panda.revert_sync('root')
        time.sleep(10)
        if extern or "panda.mount bins" in preconditions:
            panda.copy_to_guest(artifacts_dir)
            print(panda.run_serial_cmd('cd /root/bins/'))
        
        if len(preconditions) > 0:
            for cmd in preconditions:
                if cmd == "panda.mount bins":
                    pass
                else:
                    print(panda.run_serial_cmd(cmd, no_timeout=True))
        
        
        if target_cmds[0]["type"] == "run_before":
            print(panda.run_serial_cmd(target_cmds[0]["cmd"]))

        print("snapshot reverted")
        panda.run_monitor_cmd('begin_record '+recording_name)
        print('recording started')
        time.sleep(5)
        k = 5
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