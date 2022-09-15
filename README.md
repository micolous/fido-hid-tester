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
Sending INIT...
>>> [00, ff, ff, ff, ff, 86, 00, 08, 1a, 72, 52, 3a, 20, 42, c5, 9c, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00]
>>> U2FHIDFrame { cid: 4294967295, cmd: 134, data: [26, 114, 82, 58, 32, 66, 197, 156] }
<<< [ff, ff, ff, ff, 86, 00, 11, 1a, 72, 52, 3a, 20, 42, c5, 9c, b2, e5, 1d, a3, 02, 01, 06, 07, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00]
<<< U2FHIDResponseFrame { cid: 4294967295, payload: INIT(InitResponse { nonce: [26, 114, 82, 58, 32, 66, 197, 156], cid: 3001359779, protocol_version: 2, device_version_major: 1, device_version_minor: 6, device_version_build: 7, capabilities: 0 }) }
Protocol v2, Device v1.6.7, Capabilities 0x00
Sending properly formed VERSION request...
>>> [00, b2, e5, 1d, a3, 83, 00, 07, 00, 03, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00]
>>> U2FHIDFrame { cid: 3001359779, cmd: 131, data: [0, 3, 0, 0, 0, 0, 0] }
<<< [b2, e5, 1d, a3, 83, 00, 08, 55, 32, 46, 5f, 56, 32, 90, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00]
<<< U2FHIDResponseFrame { cid: 3001359779, payload: MSG(MessageResponse { data: [85, 50, 70, 95, 86, 50], sw1: 144, sw2: 0 }) }
Sending malformed VERSION request...
>>> [00, b2, e5, 1d, a3, 83, 00, 09, 00, 03, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00]
>>> U2FHIDFrame { cid: 3001359779, cmd: 131, data: [0, 3, 0, 0, 0, 0, 0, 0, 0] }
<<< [b2, e5, 1d, a3, 83, 00, 08, 55, 32, 46, 5f, 56, 32, 90, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00]
<<< U2FHIDResponseFrame { cid: 3001359779, payload: MSG(MessageResponse { data: [85, 50, 70, 95, 86, 50], sw1: 144, sw2: 0 }) }
Device responded normally to bad request!

[...]

Final report:

0 device(s) reported ERROR for bad GET_VERSION request:

3 device(s) reported OK for bad GET_VERSION request:
- 2581:f1d0: Plug-up Plug-up
- 20a0:42b1: Nitrokey Nitrokey FIDO2 2.0.0
- 1050:0402: Yubico YubiKey FIDO

0 device(s) only accepted bad GET_VERSION request:

0 device(s) don't support FIDOv1:

0 device(s) reported some other issue
```

## Reference material

* [FIDO U2F v1.2 HID protocol](https://fidoalliance.org/specs/fido-u2f-v1.2-ps-20170411/fido-u2f-hid-protocol-v1.2-ps-20170411.html)
* [FIDO U2F v1.2 Raw Message Formats](https://fidoalliance.org/specs/fido-u2f-v1.2-ps-20170411/fido-u2f-raw-message-formats-v1.2-ps-20170411.html)
* [u2f_hid.h](https://fidoalliance.org/specs/fido-u2f-v1.2-ps-20170411/inc/u2f_hid.h)
