#--------------------------------------
# File: glob_conf.py
#
# Purpose: Global Configuration for the tool
#--------------------------------------
from hy2.core.constants import singleton
from hy2.core.termui import showConfig

@singleton
class GlobalConfig:
    def __init__(self):
        # Target Configuration Options:
        self.static_enabled = False
        self.enable_backedge_analysis = False
        self.enable_multithread_analysis = False
        
        self.guest_image = ""
        self.target_space = ""
        self.snapshot_name = ""
        self.kernel_symbols_file = ""
        self.target_path = ""
        self.mount_path = ""
        self.max_static_depth = 10
        self.property_dir = ""
        self.dumps_path = ""
        self.show_infeasible = True

        # PANDA backend: "auto" (docker if pandare isn't installed), "docker" or "native"
        self.panda_backend = "auto"
        self.docker_image = "hy2-panda"
        self.docker_cmd = "docker"
        self.docker_extra_args = []
        
    def toStr(self):
        properties = {'enable_static_analysis': self.static_enabled, "target_space": self.target_space, "snapshot": self.snapshot_name}
        showConfig(properties)
