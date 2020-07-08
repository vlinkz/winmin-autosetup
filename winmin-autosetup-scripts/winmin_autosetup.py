#!/usr/bin/env python3
import os,subprocess,sys,shutil,grp
import re
import argparse
import magic
from clint.textui import progress
import requests
import xml.etree.ElementTree as ET
import getpass
import socket

def createvm(virtiowin):
    try:
      subprocess.check_call("virsh undefine winmin-base > /dev/null 2>&1", shell=True)
    except:
        pass
    if os.path.exists("/var/lib/libvirt/images/winmin-base.qcow2"):
        subprocess.call(["virsh","vol-delete","/var/lib/libvirt/images/winmin-base.qcow2"])
    subprocess.call("sudo qemu-img create -f qcow2 /var/lib/libvirt/images/winmin-base.qcow2 50G",shell=True)
    subprocess.call(["virt-install","--virt-type=kvm","--name=winmin-base","--ram","4096","--vcpus","4","--hvm","--network","network=default,model=virtio","--graphics","spice,listen=socket","--disk","/var/lib/libvirt/images/winmin-base.qcow2,bus=virtio,cache=none,io=native,format=qcow2","--cdrom","/tmp/winmin-autosetup/winauto.iso","--disk","{},device=cdrom".format(virtiowin),"--video","qxl","--os-variant","win10"])

def modifyiso(winiso,prodkey,sambapass):
    os.makedirs("/tmp/winmin-autosetup/iso")
    subprocess.call(["7z","x",winiso,"-o/tmp/winmin-autosetup/iso"])
    for file in os.listdir("/usr/share/winmin-autosetup/"):
        shutil.copyfile("/usr/share/winmin-autosetup/{}".format(file),"/tmp/winmin-autosetup/iso/{}".format(file))

    subprocess.call("wiminfo /tmp/winmin-autosetup/iso/sources/boot.wim --extract-xml /tmp/winmin-autosetup/wim.xml",shell=True)
    tree = ET.parse("/tmp/winmin-autosetup/wim.xml")
    root = tree.getroot()
    lang = root.find("IMAGE").find("WINDOWS").find("LANGUAGES").find("LANGUAGE").text

    read = open("/usr/share/winmin-autosetup/autounattend.xml", "rt")
    out = open("/tmp/winmin-autosetup/iso/autounattend.xml", "wt")
    for line in read:
        line = line.replace("{{LANG}}",lang)
        line = line.replace("{{PRODKEY}}",prodkey)
        out.write(line)
    read.close()
    out.close()

    #Temporary samba setup
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 0))
    ip = s.getsockname()[0]

    out = open("/tmp/winmin-autosetup/iso/sambainfo.txt", "wt")
    out.write(ip+"\n")
    out.write(os.environ.get("USER")+"\n")
    out.write(sambapass)
    out.close()

    subprocess.call(["genisoimage","-allow-limited-size","-b","boot/etfsboot.com","-no-emul-boot","-boot-load-size","8","-iso-level","2","-udf","-joliet","-D","-N","-relaxed-filenames","-o","/tmp/winmin-autosetup/winauto.iso","/tmp/winmin-autosetup/iso"])

def virtiowindl():
    print("No virtio-win ISO specified!")
    val = input("Would you like to download now? [Y/n] ")
    if val in ["n","N","no","No"]:
        print("Exiting!")
        exit(0)
    os.makedirs("/tmp/winmin-autosetup")

    r = requests.get("https://fedorapeople.org/groups/virt/virtio-win/direct-downloads/latest-virtio/virtio-win.iso", stream=True)
    path = "/tmp/winmin-autosetup/virtio-win.iso"
    with open(path, 'wb') as f:
        total_length = int(r.headers.get('content-length'))
        for chunk in progress.bar(r.iter_content(chunk_size=1024), expected_size=(total_length/1024) + 1): 
            if chunk:
                f.write(chunk)
                f.flush()

def main():
    parser = argparse.ArgumentParser(description='Automatically setup winmin.')

    parser.add_argument("winiso", metavar="windows_iso", type=str, help="The Windows 10 installer ISO (MUST be May 2020 update or later)")
    parser.add_argument("prodkey", metavar="product_key", type=str, help="Windows 10 product key")
    parser.add_argument("virtiowin", metavar="virtio-win_iso", type=str, nargs="?", help="Location of the virtio-win iso")
    args=parser.parse_args()

    groups = [grp.getgrgid(g).gr_name for g in os.getgroups()]
    if "kvm" and "tty" not in groups:
        print("User is not part of the kvm and tty groups")
        exit(0)

    if not os.path.isfile(args.winiso):
      print("Input is not a valid file, exiting")
      exit(0)
    if magic.from_file(args.winiso,mime=True) != "application/x-iso9660-image":
      print("Input is not a valid ISO, exiting")
      exit(0)
    winiso = os.path.realpath(args.winiso)

    prodkey = args.prodkey
    if not re.match("[A-Za-z0-9]{5}-[A-Za-z0-9]{5}-[A-Za-z0-9]{5}-[A-Za-z0-9]{5}-[A-Za-z0-9]{5}",prodkey):
        print("Incorrect product key format")
        exit(1)

    if os.path.exists("/tmp/winmin-autosetup"):
        shutil.rmtree("/tmp/winmin-autosetup")

    virtiowin = args.virtiowin
    if virtiowin == None:
        virtiowindl()
        virtiowin = "/tmp/winmin-autosetup/virtio-win.iso"
    virtiowin = os.path.realpath(virtiowin)

    #Temporary samba setup until the virtio-win viofs driver is finished
    if not os.path.isfile("/etc/samba/smb.conf"):
        print("Samba config not found")
        exit(1)
    user = os.environ.get("USER")
    sambapass = getpass.getpass("Enter new samba server password: ")
    print("Need permission to edit smb.conf with sudo")
    smbedited = False
    for line in open("/etc/samba/smb.conf","r"):
      if "winmin" in line:
          smbedited = True
    if not smbedited:
      os.system("echo 'cat /usr/share/winmin-autosetup/smb.conf >> /etc/samba/smb.conf' | sudo -s")
    os.system("echo \'(echo {}; echo {}) | smbpasswd -s -a {}; systemctl enable smbd; systemctl restart smbd\' | sudo -s".format(sambapass,sambapass,user))



    modifyiso(winiso,prodkey,sambapass)

    createvm(virtiowin)
    subprocess.call("virsh change-media winmin-base sda --eject",shell=True)
    subprocess.call("virsh change-media winmin-base sdb --eject",shell=True)

    shutil.rmtree("/tmp/winmin-autosetup")
    print("Done!")

if __name__ == "__main__":
    main();