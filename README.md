# fido-hid-tester

This tool tests FIDO v1/U2F USB keys for how they handle [malformed GET_VERSION requests](https://github.com/mozilla/authenticator-rs/issues/190).

This only supports FIDO v1 U2F USB HID keys, and won't support other things.

Don't use this as a reference for the FIDO spec, it doesn't implement much at all!

## Building and running

1. [Install a Rust toolchain (rustup)](https://www.rust-lang.org/tools/install)
2. `cargo run` (builds and runs the program)

This will test every U2F USB HID device attached to your computer, and give you a protocol trace:

```
% cargo run
   Compiling fido-hid-tester v0.1.0 (~/fido-hid-tester)
    Finished dev [unoptimized + debuginfo] target(s) in 0.37s
     Running `target/debug/fido-hid-tester`

Testing device 2581:f1d0: Plug-up Plug-up
Sending INIT
>>> [0, 255, 255, 255, 255, 134, 0, 8, 93, 135, 250, 22, 174, 230, 234, 206, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
<<< [255, 255, 255, 255, 134, 0, 17, 93, 135, 250, 22, 174, 230, 234, 206, 8, 135, 35, 202, 2, 1, 6, 7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
<<< U2FHIDResponseFrame { cid: 4294967295, payload: INIT(InitResponse { nonce: [93, 135, 250, 22, 174, 230, 234, 206], cid: 143074250, protocol_version: 2, device_version_major: 1, device_version_minor: 6, device_version_build: 7, capabilities: 0 }) }
Protocol v2, Device v1.6.7, Capabilities 0x00
Sending properly formed VERSION request...
>>> [0, 8, 135, 35, 202, 131, 0, 7, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
<<< [8, 135, 35, 202, 131, 0, 8, 85, 50, 70, 95, 86, 50, 144, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
<<< U2FHIDResponseFrame { cid: 143074250, payload: MSG([85, 50, 70, 95, 86, 50, 144, 0]) }
Sending malformed VERSION request...
>>> [0, 8, 135, 35, 202, 131, 0, 9, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
<<< [8, 135, 35, 202, 131, 0, 8, 85, 50, 70, 95, 86, 50, 144, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
<<< U2FHIDResponseFrame { cid: 143074250, payload: MSG([85, 50, 70, 95, 86, 50, 144, 0]) }
Device responded normally to bad request!

[...]

Final report:

0 device(s) reported ERROR for bad GET_VERSION request:

5 device(s) reported OK for bad GET_VERSION request:
- 2581:f1d0: Plug-up Plug-up
- 20a0:42b1: Nitrokey Nitrokey FIDO2 2.0.0
- 2581:f1d0: Plug-up Plug-up
- 1050:0402: Yubico YubiKey FIDO
- 2581:f1d0: Plug-up Plug-up

0 device(s) only accepted bad GET_VERSION request:

0 device(s) didn't accept any GET_VERSION request, and probably don't support FIDOv1:

0 device(s) reported some other issue
```

## Reference material

* [FIDO U2F v1.2 HID protocol](https://fidoalliance.org/specs/fido-u2f-v1.2-ps-20170411/fido-u2f-hid-protocol-v1.2-ps-20170411.html)
* [FIDO U2F v1.2 Raw Message Formats](https://fidoalliance.org/specs/fido-u2f-v1.2-ps-20170411/fido-u2f-raw-message-formats-v1.2-ps-20170411.html)
* [u2f_hid.h](https://fidoalliance.org/specs/fido-u2f-v1.2-ps-20170411/inc/u2f_hid.h)
