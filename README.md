# fido-hid-tester

This tool tests FIDO v1/U2F USB keys for how they handle [malformed GET_VERSION requests](https://github.com/mozilla/authenticator-rs/issues/190).

FIDO v1.0, v2.0 and v2.1 describe ISO 7816 command length (L<sub>c</sub>) and response length (L<sub>e</sub>) incorrectly: when N<sub>c</sub> = 0, there are no L<sub>c</sub> bytes. This encoding is adapted from ISO 7816-4:2005 extended APDUs (section 5.1, "Command-response pairs").

For example, a `GET_VERSION` request (which has no command data, so N<sub>c</sub> = 0) with N<sub>e</sub> = 65536 [should be](https://fidoalliance.org/specs/fido-u2f-v1.2-ps-20170411/fido-u2f-raw-message-formats-v1.2-ps-20170411.html#getversion-request-and-response---u2f_version):

`(CLA)00 (INS)03 (P1)00 (P2)00 (Le)00 00 00`

But instead, those versions of the spec incorrectly add L<sub>c</sub> bytes:

`(CLA)00 (INS)03 (P1)00 (P2)00 (Lc)00 00 00 (Le)00 00`

This test program checks which versions of the command work with all FIDO v1 *USB* U2F keys attached to your computer.  This *doesn't support* other transports like BLE or NFC, and *can't test* FIDO v2-only keys.

Don't use this as a reference for the FIDO spec, it doesn't implement much at all!  However, this tool may be a useful starting point for *fuzzing* the keys – many keys handle invalid inputs differently. 🙃

## Requirements

* [Install a Rust toolchain (rustup)][rustup] which supports [Rust 2018][rust18] (or later).

* One or more FIDO v1 compatible U2F USB keys to test.

  This software selects devices by USB usage page (`0xf1d0` / `0x01`), so it should work with uncommon and not-publicly-available keys (which comply with the FIDO specification).

* Ensure your current user has permission to directly communicate with USB HID FIDO devices:

  * 🐧 **Linux** may need additional `udev` rules (depending on distribution). [Before `udev` 244][udev], U2F rules are specified by product/vendor ID (rather than usage page), which only include common, publicly-available keys.

  * 🍏 **macOS** should just work out-of-the-box, no special permissions required.

  * 🪟 **Windows** versions with [WebAuthn API][win10] (Windows 10 build 1903 and later) require running this tool as Administrator.

    If you don't, you'll get an error: `No FIDO U2FHID compatible USB devices detected!`

    Windows' [WebAuthn API blocks direct access to all FIDO security keys][win10] in favour of its own WebAuthn API. Unfortunately, this is not low level enough for this tool to work.

[rustup]: https://www.rust-lang.org/tools/install
[rust18]: https://doc.rust-lang.org/edition-guide/rust-2018/index.html
[udev]: https://github.com/systemd/systemd/pull/13357
[win10]: https://docs.microsoft.com/en-us/windows/security/identity-protection/hello-for-business/webauthn-apis

## Building and running

Build and run with: `cargo run`

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

## Results

Each device is listed with its USB vendor ID (`idVendor`), product ID (`idProduct`), manufacturer string (`iManufacturer`) and product string (`iProduct`).

The tool will classify all devices into one of these categories:

### ...ERROR for bad GET_VERSION request

The device responded to a well-formed FIDOv1 `GET_VERSION` request with `U2F_V2`, but returned some sort of error for a malformed request.

This is the correct behaviour according to the FIDO v1.1 and v1.2 spec, but the key may not work correctly with Mozilla's Authenticator library due to [a bug](https://github.com/mozilla/authenticator-rs/issues/190).

### ...OK for bad GET_VERSION request

The device responded to both well-formed and malformed FIDOv1 `GET_VERSION` requests with `U2F_V2`.

This makes the key compatible with software which followed the FIDO v1.0 spec's *incorrect* description of ISO 7816, as well as those following FIDO v1.1 and v1.2's correct description.

*Most keys I've tested do this.*

### ...only accepted bad GET_VERSION request

The device responded to a malformed FIDOv1 `GET_VERSION` request with `U2F_V2`, but returned some sort of error for a correctly-formed request.

This suggests that the key followed FIDO v1.0 spec's incorrect description of ISO 7816, and is **not** compliant with FIDO v1.1 and v1.2.

*A key in this category is defective, and should be returned to the manufacturer for replacement or refund.*

### ...don't support FIDOv1

The device may not be affected by this issue because it doesn't support FIDO v1 (probably because it has been disabled).

USB FIDO v2 devices can operate in two modes, both of which are not directly affected by this bug:

* Using `U2FHID_MSG`, FIDO v2 commands are wrapped in ISO 7816 APDUs, but always have command data (so never use N<sub>c</sub> = 0).

* Using `U2FHID_CBOR`, FIDO v2 commands are sent "directly", not wrapped in ISO 7816 APDUs, so are not affected by this bug.

*A key in this category can't be tested by this tool.*

### ...reported some other issue

Something else went wrong communicating with the key which this tool doesn't know how to handle.

This could indicate some other program has exclusive access to the key, or could be because of [permission issues](#requirements).

## Reference material

* [FIDO U2F v1.2 HID protocol](https://fidoalliance.org/specs/fido-u2f-v1.2-ps-20170411/fido-u2f-hid-protocol-v1.2-ps-20170411.html)
* [FIDO U2F v1.2 Raw Message Formats](https://fidoalliance.org/specs/fido-u2f-v1.2-ps-20170411/fido-u2f-raw-message-formats-v1.2-ps-20170411.html)
* [u2f_hid.h](https://fidoalliance.org/specs/fido-u2f-v1.2-ps-20170411/inc/u2f_hid.h)
