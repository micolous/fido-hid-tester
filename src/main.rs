// fido-hid-tester/main.rs
// Test program for https://github.com/mozilla/authenticator-rs/issues/190
//
// Copyright 2022 Michael Farrell <micolous+git@gmail.com>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

extern crate hidapi;
extern crate rand;

use hidapi::{DeviceInfo, HidApi, HidDevice};
use rand::prelude::*;
use std::convert::{From, TryFrom};

// u2f_hid.h
const FIDO_USAGE_PAGE: u16 = 0xf1d0;
const FIDO_USAGE_U2FHID: u16 = 0x01;
const HID_RPT_SIZE: usize = 64;
const U2FHID_TRANS_TIMEOUT: i32 = 3000;

const TYPE_INIT: u8 = 0x80;
const U2FHID_MSG: u8 = TYPE_INIT | 0x03;
const U2FHID_INIT: u8 = TYPE_INIT | 0x06;
const U2FHID_ERROR: u8 = TYPE_INIT | 0x3f;
const CAPABILITY_NMSG: u8 = 0x08;

const CID_BROADCAST: u32 = 0xffffffff;

const U2F_VERSION_REQ: [u8; 7] = [0, 3, 0, 0, 0, 0, 0];
const U2F_VERSION_EXPECTED: [u8; 6] = [
    0x55, 0x32, 0x46, 0x5F, 0x56, 0x32, // U2F_V2
];
// https://github.com/mozilla/authenticator-rs/issues/190
const U2F_VERSION_REQ_BAD: [u8; 9] = [0, 3, 0, 0, 0, 0, 0, 0, 0];

/// U2F HID request frame type
#[derive(Debug)]
struct U2FHIDFrame<'a> {
    /// Channel identifier
    cid: u32,
    /// Command identifier
    cmd: u8,
    // len: u16,
    /// Payload data
    data: &'a [u8],
}

impl Into<Vec<u8>> for &U2FHIDFrame<'_> {
    /// Serialises a U2FHIDFrame to bytes to be send via a USB HID report
    fn into(self) -> Vec<u8> {
        // This does not implement fragmentation / continuation packets!

        let mut o: Vec<u8> = vec![0; HID_RPT_SIZE + 1];
        // o[0] = 0; (Report ID)
        o[1] = (self.cid >> 24) as u8;
        o[2] = (self.cid >> 16) as u8;
        o[3] = (self.cid >> 8) as u8;
        o[4] = self.cid as u8;
        o[5] = self.cmd;

        if self.data.len() + 8 > o.len() {
            panic!("Data payload too long");
        }
        o[6] = (self.data.len() >> 8) as u8;
        o[7] = self.data.len() as u8;
        o[8..8 + self.data.len()].copy_from_slice(&self.data);

        o
    }
}

impl U2FHIDFrame<'_> {
    /// Sends a single message to a U2F device
    fn send(&self, dev: &HidDevice) {
        let d: Vec<u8> = self.into();
        println!(">>> {:02x?}", d);
        println!(">>> {:?}", self);
        dev.write(&d).expect("Error writing to device");
    }
}

#[derive(Debug)]
struct InitResponse {
    nonce: Vec<u8>,
    /// Allocated channel identifier
    cid: u32,
    /// U2F protocol version (2)
    protocol_version: u8,
    device_version_major: u8,
    device_version_minor: u8,
    device_version_build: u8,
    capabilities: u8,
}

impl TryFrom<&[u8]> for InitResponse {
    type Error = ();
    fn try_from(d: &[u8]) -> Result<Self, Self::Error> {
        if d.len() < 17 {
            return Err(());
        }
        Ok(InitResponse {
            nonce: (&d[..8]).to_vec(),
            cid: (d[8] as u32) << 24 | (d[9] as u32) << 16 | (d[10] as u32) << 8 | d[11] as u32,
            protocol_version: d[12],
            device_version_major: d[13],
            device_version_minor: d[14],
            device_version_build: d[15],
            capabilities: d[16],
        })
    }
}

/// CTAPv1 APDU (ISO 7816-like)
#[derive(Debug, PartialEq)]
struct MessageResponse {
    /// Data payload
    data: Vec<u8>,
    /// Status byte 1
    sw1: u8,
    /// Status byte 2
    sw2: u8,
}

impl MessageResponse {
    /// Did we get a simple "ok" response?
    fn is_ok(&self) -> bool {
        self.sw1 == 0x90 && self.sw2 == 0
    }
}

impl TryFrom<&[u8]> for MessageResponse {
    type Error = ();
    fn try_from(d: &[u8]) -> Result<Self, Self::Error> {
        if d.len() < 2 {
            return Err(());
        }
        Ok(MessageResponse {
            data: d[..d.len() - 2].to_vec(),
            sw1: d[d.len() - 2],
            sw2: d[d.len() - 1],
        })
    }
}

#[derive(Debug)]
enum U2FError {
    None,
    InvalidCommand,
    InvalidParameter,
    InvalidMessageLength,
    InvalidMessageSequencing,
    MessageTimeout,
    ChannelBusy,
    ChannelRequiresLock,
    SyncCommandFailed,
    Unspecified,
    Unknown,
}

impl From<u8> for U2FError {
    fn from(v: u8) -> Self {
        match v {
            0x00 => U2FError::None,
            0x01 => U2FError::InvalidCommand,
            0x02 => U2FError::InvalidParameter,
            0x03 => U2FError::InvalidMessageLength,
            0x04 => U2FError::InvalidMessageSequencing,
            0x05 => U2FError::MessageTimeout,
            0x06 => U2FError::ChannelBusy,
            0x0a => U2FError::ChannelRequiresLock,
            0x0b => U2FError::SyncCommandFailed,
            0x7f => U2FError::Unspecified,
            _ => U2FError::Unknown,
        }
    }
}

impl From<&[u8]> for U2FError {
    fn from(d: &[u8]) -> Self {
        if d.len() >= 1 {
            U2FError::from(d[0])
        } else {
            U2FError::Unknown
        }
    }
}

#[derive(Debug)]
enum Payload {
    INIT(InitResponse),
    MSG(MessageResponse),
    ERROR(U2FError),
    UNKNOWN,
}

/// U2F HID response frame type
#[derive(Debug)]
struct U2FHIDResponseFrame {
    cid: u32,
    payload: Payload,
}

impl From<&[u8]> for U2FHIDResponseFrame {
    /// Deserialize a U2FHID payload
    fn from(b: &[u8]) -> Self {
        let len = (b[5] as usize) << 8 | b[6] as usize;
        let data = if len == 0 || len > b.len() + 7 {
            None
        } else {
            Some(&b[7..7 + len])
        };

        let payload = match data {
            Some(d) => match b[4] {
                U2FHID_INIT => InitResponse::try_from(d)
                    .map(Payload::INIT)
                    .unwrap_or(Payload::UNKNOWN),
                U2FHID_MSG => MessageResponse::try_from(d)
                    .map(Payload::MSG)
                    .unwrap_or(Payload::UNKNOWN),
                U2FHID_ERROR => Payload::ERROR(U2FError::from(d)),
                _ => Payload::UNKNOWN,
            },
            None => Payload::UNKNOWN,
        };

        U2FHIDResponseFrame {
            cid: (b[0] as u32) << 24 | (b[1] as u32) << 16 | (b[2] as u32) << 8 | b[3] as u32,
            payload,
        }
    }
}

impl U2FHIDResponseFrame {
    /// Receives a single message from a U2F device
    fn recv(dev: &HidDevice, cid: u32) -> Self {
        let mut ret: Vec<u8> = vec![0; HID_RPT_SIZE];

        let len = dev
            .read_timeout(&mut ret, U2FHID_TRANS_TIMEOUT)
            .expect("failure reading");

        println!("<<< {:02x?}", &ret[..len]);
        let r = Self::from(&ret[..len]);
        println!("<<< {:?}", r);
        assert_eq!(cid, r.cid);
        r
    }
}

fn list_devices(label: &str, devices: &[(String, &DeviceInfo)]) {
    println!("");
    if devices.is_empty() {
        println!("No devices {}.", label);
        return;
    }
    println!(
        "{} device{} {}:",
        devices.len(),
        if devices.len() > 1 { "s" } else { "" },
        label
    );
    for (name, device) in devices {
        println!(
            "- {:04x}:{:04x}: {}",
            device.vendor_id(),
            device.product_id(),
            name
        );
    }
}

fn main() {
    let mut rng = rand::thread_rng();

    let api = HidApi::new().unwrap();
    let fido_devices: Vec<&DeviceInfo> = api
        .device_list()
        .filter(|d| d.usage_page() == FIDO_USAGE_PAGE && d.usage() == FIDO_USAGE_U2FHID)
        .collect();

    if fido_devices.len() == 0 {
        panic!("No FIDO U2FHID compatible USB devices detected!");
    }

    let mut no_fido1: Vec<(String, &DeviceInfo)> = Vec::new();
    let mut bad_only: Vec<(String, &DeviceInfo)> = Vec::new();
    let mut bad_ok: Vec<(String, &DeviceInfo)> = Vec::new();
    let mut bad_err: Vec<(String, &DeviceInfo)> = Vec::new();

    // Print out information about all connected devices
    for device in &fido_devices {
        let name: String = match (device.manufacturer_string(), device.product_string()) {
            (Some(m), Some(p)) => format!("{} {}", m, p),
            (Some(m), _) => m.to_string(),
            (_, Some(p)) => p.to_string(),
            _ => String::new(),
        };
        println!();
        println!(
            "Testing device {:04x}:{:04x}: {}",
            device.vendor_id(),
            device.product_id(),
            name,
        );

        // Open a channel
        let channel = device.open_device(&api).expect("Could not open device");

        // INIT command
        let mut nonce: [u8; 8] = [0; 8];
        rng.fill_bytes(&mut nonce);

        println!("Sending INIT...");
        U2FHIDFrame {
            cid: CID_BROADCAST,
            cmd: U2FHID_INIT,
            data: &nonce,
        }
        .send(&channel);
        let res = U2FHIDResponseFrame::recv(&channel, CID_BROADCAST);
        let cid: u32 = match res.payload {
            Payload::INIT(i) => {
                // check nonce
                if i.nonce != &nonce {
                    println!("Unexpected nonce value!");
                    continue;
                }

                println!(
                    "Protocol v{}, Device v{}.{}.{}, Capabilities 0x{:02x}",
                    i.protocol_version,
                    i.device_version_major,
                    i.device_version_minor,
                    i.device_version_build,
                    i.capabilities
                );

                if i.capabilities & CAPABILITY_NMSG == CAPABILITY_NMSG {
                    println!("Device set CAPABILITY_NMSG, does not support FIDOv1");
                    no_fido1.push((name, device));
                    continue;
                }

                i.cid
            }
            o => {
                println!("Unexpected response: {:?}", o);
                continue;
            }
        };

        // We now have a channel to talk on.
        println!("Sending properly formed VERSION request...");
        U2FHIDFrame {
            cid,
            cmd: U2FHID_MSG,
            data: &U2F_VERSION_REQ,
        }
        .send(&channel);
        let res = U2FHIDResponseFrame::recv(&channel, cid);
        let mut ver_err = false;
        match res.payload {
            Payload::MSG(m) => {
                if !m.is_ok() {
                    println!("Got non-OK response on ISO7816 level, probably an error");
                    println!(
                        "The device may not support FIDOv1? Otherwise this is a protocol violation."
                    );
                    ver_err = true;
                } else if m.data != &U2F_VERSION_EXPECTED {
                    println!("Unexpected version response!");
                    continue;
                }
            }
            Payload::ERROR(e) => {
                println!("Device responded with error: {:?}", e);
                println!(
                    "The device may not support FIDOv1? Otherwise this is a protocol violation."
                );
                ver_err = true;
            }
            _ => {
                println!("Unexpected response type!");
                continue;
            }
        }

        println!("Sending malformed VERSION request...");
        U2FHIDFrame {
            cid,
            cmd: U2FHID_MSG,
            data: &U2F_VERSION_REQ_BAD,
        }
        .send(&channel);
        let res = U2FHIDResponseFrame::recv(&channel, cid);

        match res.payload {
            Payload::MSG(m) => {
                if m.is_ok() {
                    if m.data == &U2F_VERSION_EXPECTED {
                        println!("Device responded normally to bad request!");
                        if ver_err {
                            println!(
                                "Correct request returned an error, so this is a protocol violation!"
                            );
                            bad_only.push((name, device));
                        } else {
                            bad_ok.push((name, device));
                        }
                    } else {
                        println!("Unexpected version response!");
                        continue;
                    }
                } else {
                    println!("Got non-OK response on ISO7816 level, probably an error");
                    if ver_err {
                        println!("This device doesn't support FIDOv1.");
                        no_fido1.push((name, device));
                    } else {
                        bad_err.push((name, device));
                    }
                }
            }
            Payload::ERROR(e) => {
                println!("Device responded with error: {:?}", e);
                if ver_err {
                    println!("This device doesn't support FIDOv1.");
                    no_fido1.push((name, device));
                } else {
                    bad_err.push((name, device));
                }
            }
            _ => {
                println!("Unexpected response type!");
                continue;
            }
        }
    }

    println!("");
    println!("Final report:");
    list_devices("reported ERROR for bad GET_VERSION request", &bad_err);
    list_devices("reported OK for bad GET_VERSION request", &bad_ok);
    list_devices(
        "only accepted bad GET_VERSION request (defective!)",
        &bad_only,
    );
    list_devices("don't support FIDOv1", &no_fido1);

    let other_issues =
        fido_devices.len() - bad_ok.len() - bad_err.len() - bad_only.len() - no_fido1.len();
    if other_issues > 0 {
        println!("");
        println!(
            "{} device(s) reported some other issue, check the log!",
            other_issues
        );
    }
}
