race_replay.py is the real point of this repo. It is intended to test for race conditions in web applications using the last frame synchronization method as done in the original h2tinker example.

# H2Tinker: Da symys fork!

I had to modify h2tinker a little to get it to play nice with mitmproxy. I shoddily repacked scapy 2.4.3 for nix to use it with a nix-shell, defined in `shell.nix`. If I have time and motivation, I might want to try updating the dependence on scapy, to bump the scapy version, but it seems like it might be a big job.

H2Tinker is a minimalistic low-level HTTP/2 client implementation in Python.

It is based on [scapy](https://github.com/secdev/scapy) and also enables directly sending scapy-crafted frames. On top of scapy, H2Tinker provides
* HTTP/2 connection setup and management,
* TCP and TLS connection setup and management,
* a user-friendly documented and typed API for creating different frames and requests,
* documentation and examples on how different attacks can be implemented.

## Installation and Usage

This only works with mitmproxy on nix right now. cd into the repo, use the shell.nix to create a virtual environment, and then run mitmproxy:
```
nix-shell
mitmproxy -s race_replay.py
```

Then in mitmproxy, select whichever flows you want to use to attempt to construct a race condition. Maybe using duplicates with modified parameters... Or maybe just a bunch of different flows, whatever you want, but right now the connection is based on the host in the first request in the flow sequence. The intended use is to mark a bunch of flows and then run:
```
:race_replay @marked
```
