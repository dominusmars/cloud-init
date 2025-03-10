# Windows Cloud-Init For OpenStack and Proxmox

This is a simple cloud-init service which will locate cloud config files on Windows and execute commands to initilize the system.

## Installation

clone the repo and run the install.ps1 script as administrator.
this will create a cloud-init service and install the required files into the system.

## Logging

Located at C:\cloud-init\logs\cloud-init.log

## Reset Cloud-Init

Remove the first-boot-complete file located at C:\cloud-init\logs\first-boot-complete
