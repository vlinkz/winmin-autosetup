# Winmin Autosetup

Winmin Autosetup is a python script that automatically installs a [libvirt](https://libvirt.org/) virtual machine as a base for Winmin.

# Build Dependencies

- python3

# Building

Build and install with:

```
$ sudo python3 setup.py install
```
# Runtime Dependencies

- python3
- python3-magic
- python3-clint
- python3-requests
- samba
- libvirt-clients
- libvirt-daemon-system
- virtinst
- virt-viewer
- wimtools

# Setup

To access the spice socket of the guest VM, the user must be part of the `kvm` group. This can be added using the following command.
```
$ sudo usermod -aG $USER kvm
```
In order to interact with the guest serial port, the user must be part of the `tty` group. This can be added using the following command.
```
$ sudo usermod -aG $USER tty
```
You may need to logout or reboot in order for group changes to take effect.

# Running

## winmin-autosetup

Uses Microsoft's autounattended process to setup a a virtual machine to be used for winmin. 

### Usage
```
winmin-autosetup [-h] windows_iso product_key [virtio-win_iso]
```
### Examples
```
winmin-autosetup ./Win10.iso XXXXX-XXXXX-XXXXX-XXXXX-XXXXX

winmin-autosetup ./Win10.iso XXXXX-XXXXX-XXXXX-XXXXX-XXXXX ./virtio-win.iso
```

# TODO
- Setup using [virtio-fs](https://virtio-fs.gitlab.io/) once the [viofs Windows driver](https://github.com/virtio-win/kvm-guest-drivers-windows/tree/master/viofs) is completed

