# TLS-MITM-VDA
Paper: Return of Version Downgrade Attack in the Era of TLS 1.3

This script is the script used in the TLS version downgrade assessment, and runs in python3.

## Running
```bash
$ sudo apt-get install build-essential libnetfilter-queue-dev
$ sudo pip3 install netfilterqueue scapy 

$ sudo python3 mitm.py
```

## Inputs
Network Interface: Enter the network interface you use in assessment(e.g. ens33)

Client IP: Enter the client(Browser, victim) IP address

Server IP: Enter the server(for local web server) or gateway(for public web server) IP address


TCP Flag: Enter the type to use for session termination(default: FA)

Target TLS version: Enter the TLS version to downgrade(default: befor TLS 1.2)


