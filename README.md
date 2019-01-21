# PrivExchange
POC tools accompanying the blog [Abusing Exchange: One API call away from Domain Admin](https://dirkjanm.io/abusing-exchange-one-api-call-away-from-domain-admin/).

## Requirements
These tools require [impacket](https://github.com/SecureAuthCorp/impacket). You can install it from pip with `pip install impacket`, but it is recommended to use the latest version from GitHub.

## privexchange.py
This tool simply logs in on Exchange Web Services to subscribe to push notifications. This will make Exchange connect back to you and authenticate as system.

## httpattack.py
Attack module that can be used with ntlmrelayx.py to perform the attack without credentials. To get it working:
- Modify the attacker URL in `httpattack.py` to point to the attacker's server where ntlmrelayx will run
- Clone impacket from GitHub `git clone https://github.com/SecureAuthCorp/impacket`
- Copy this file into the `/impacket/impacket/examples/ntlmrelayx/attacks/` directory.
- `cd impacket`
- Install the modified version of impacket with `pip install . --upgrade` or `pip install -e .`