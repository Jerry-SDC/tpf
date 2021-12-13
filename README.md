# tpf
Tiny packet forwarder

## run

Simple run the following command, it will read the rules from 'config.json'.
```
gopf
```

you can also simply specify the rules in command line:
```
gopf tcp::3389:mydomain.com:3389 udp::3389:mydomain.com:3389 tcp::2222:ssh.mydomain.com:22
```
Note:
1. whitelist is not supported if you specify rule in the command line
2. In this form, the rules in config.json will still read and active, plus the rules you specify in the command line.


## config

the config is a json file, please refer config_example.json.
copy config_example.json to config.json and make necessary, the run the application, it will read the config automatically.
