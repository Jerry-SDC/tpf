# Tiny Packet Forwarder
Usually, I use iptables on Linux to do forward. i encounter some problems sometime, for example:
1. RDP disconnect immediately after connect, i don't know why, set TCP MSS to path MTU doesn't help.
2. DNAT target in iptables seems doesn't support TCP BBR.
3. iptables works on Linux only, i use windows sometime, i didn't know the syntax to set port forward on windows.

So i write a simple tool todo the job. It just suit my needs, nothing more.

## run

Simple run the following command, it will read the rules from 'config.json'.
```
tpf_linux_amd64
```

you can also simply specify the rules in command line:
```
tpf_linux_amd64 tcp::3389:mydomain.com:3389 udp::3389:mydomain.com:3389 tcp::2222:ssh.mydomain.com:22
```
Note:
1. whitelist is not supported if you specify rule in the command line
2. In this form, the rules in config.json will still read and active, plus the rules you specify in the command line.


## config

The config is a json file, the syntax is straight, please refer config_example.json.
copy config_example.json to config.json and make necessary, the run the application, it will read the config automatically.
