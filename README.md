# fido-hid-tester

This tool tests FIDO v1/U2F USB keys for how they handle [malformed GET_VERSION requests](https://github.com/mozilla/authenticator-rs/issues/190).

This only supports FIDO v1 U2F USB HID keys, and won't support other things.

Don't use this as a reference for the FIDO spec, it doesn't implement much at all!

## Reference material

* [FIDO U2F v1.2 HID protocol](https://fidoalliance.org/specs/fido-u2f-v1.2-ps-20170411/fido-u2f-hid-protocol-v1.2-ps-20170411.html)
* [FIDO U2F v1.2 Raw Message Formats](https://fidoalliance.org/specs/fido-u2f-v1.2-ps-20170411/fido-u2f-raw-message-formats-v1.2-ps-20170411.html)
* [u2f_hid.h](https://fidoalliance.org/specs/fido-u2f-v1.2-ps-20170411/inc/u2f_hid.h)
