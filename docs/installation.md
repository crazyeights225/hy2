## Installation:

This document describes the installation and configuration of Hy2, primarily its largest dependency `panda-re`.

> NOTE: I'm sure some of this has changed since 2023, please read the panda docs!

## Recommended Specs:

- at least 16 GB of RAM
- at least 100GB HD
- AMD CPU if KVM
- Ubuntu 20.04

## Installation:

First install pandare:
```
git clone https://github.com/panda-re/panda
cd panda
./panda/scripts/install_ubuntu.sh
```
It will ask you for your root password.

Then run:
```
./install.sh
```
and you should be good to go.

### Using the pandare docker container (Ubuntu > 20.04)

See `docs/docker.md` for a full guide with an example.

pandare can't be installed natively on newer versions of Ubuntu. In that case the
orchestrators (`hy2/orch/`) run the PANDA record/replay steps inside a docker
container, and everything else runs on the host. This happens automatically when
`pandare` can't be imported on the host.

The container image (`hy2-panda`, based on `pandare/panda`) is built on first use from
`docker/panda/Dockerfile`, or build it yourself:
```
docker build -t hy2-panda docker/panda
```

The current directory, the repository and the guest image directory are mounted into the
container at the same paths, so relative paths in `config.json` and the test case files
still work. Recordings and `vmem_stream.log` are written to the current directory as usual.
The generic images that pandare downloads are cached in `~/.cache/hy2-panda/.panda`.

Options in the `globals` section of `config.json`:
```
"panda_backend": "auto",      # auto | docker | native
"docker_image": "hy2-panda",  # image to run
"docker_cmd": "docker",       # ie. "sudo docker" if your user isn't in the docker group
"docker_extra_args": []       # extra arguments for docker run
```
These can also be set with the `HY2_PANDA_BACKEND`, `HY2_DOCKER_IMAGE` and `HY2_DOCKER_CMD` environment variables.


### Seting up an Image:

#### Creating a serial port:
Follow the virsh console access section of this article:
https://fabianlee.org/2018/10/06/kvm-creating-an-ubuntu-vm-with-console-only-access/

```
Edit ‘etc/default/grub’, and append ‘console=ttyS0’ to the default boot parameters.

GRUB_CMDLINE_LINUX_DEFAULT="quiet splash console=ttyS0"

Then upgrade grub, and restart the guest.

sudo update-grub
init 6
```

#### Disabling Address Space Layer Randomization:

`TO DO: Write Me!`

#### Configuring osi:
On the guest:
```
   apt-get install build-essential linux-headers-`uname -r`
```

Follow the instructions in `panda/plugins/osi_linux`
Copying the directory `panda_plugins/osi_linux/utils/kernelinfo` to the guest, compiling it, inserting the kernel module, getting the output from `dmesg`

Copy this information (without the KERNELINFO-BEGIN and KERNELINFO-END lines, set name appropriately) into the `kernelinfo.conf`
Build/rebuild panda

#### Creating an image:

```
qemu-img convert <image file> -f <image format>  <qcow image name>.qcow2

ie:
qemu-img convert ubuntuserver.vdi -f vdi test_out.qcow2
```

#### Create a snapshot:

```
panda/build/x86_64-softmmu/panda-system-x86_64 -m 8192 -monitor stdio <image path>
```

In the QEMU UI window switch to the serial port you created earlier. This only works with display gtk, I don't know how to fix it.

Login to the guest.

In the QEMU monitor CLI:
```
savevm <snapshot name>
```

### Configuring Networking (for x86_64 only)

Networking doesn't work out the box for 64 bit images. On the guest you must do the following:
```
sudo nano /etc/systemd/network/20-wired.network
[Match]
Name=*

[Network]   
DHCP=yes

sudo systemctl start systemd-resolved
sudo systemctl start systemd-networkd
reboot
```
Then create a snapshot.