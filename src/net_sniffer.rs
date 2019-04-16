//! Check the network for devices
//!
//! Assumes you're on Linux or some system with `nmap` on the PATH

extern crate regex;

use std::fs::File;
use std::io::Read;
use std::process::Command;

const MAC_ADDR_FILE: &str = "./mac_addresses.txt";

pub struct NetSniffer {
    tracking_addresses: Vec<String>,
    mac_addr_match: regex::Regex,
    nmap_cmd: Command,
}

impl Default for NetSniffer {
    fn default() -> Self {
        let mac_addr_match =
            regex::Regex::new(r"([0-9A-Fa-f]{2}:){5}([0-9A-Fa-f]{2})")
                .expect("Unable to compile regex");

        let mut nmap_cmd = Command::new("nmap");
        nmap_cmd.arg("-sn").arg("192.168.0.1/24");

        let mut file =
            File::open(MAC_ADDR_FILE).expect("Unable to open MAC Address file");
        let mut buf = String::new();
        file.read_to_string(&mut buf).expect("Unable to read file");
        let tracking_addresses =
            buf.split('\n').map(|s| String::from(s)).collect();

        Self {
            tracking_addresses,
            mac_addr_match,
            nmap_cmd,
        }
    }
}

impl NetSniffer {
    pub fn compare_connections(&mut self) -> Vec<String> {
        let connected = self.connected_macs();
        self.tracking_addresses
            .iter()
            .filter(|s| !s.is_empty() && self.tracking_addresses.contains(s))
            .map(|s| s.clone())
            .collect()
    }

    fn connected_macs(&mut self) -> Vec<String> {
        let nmap_output =
            self.nmap_cmd.output().expect("Unable to run nmap command");
        String::from_utf8(nmap_output.stdout)
            .expect("Unable to convert nmap output")
            .split('\n')
            .filter(|line| line.starts_with("MAC Address:"))
            .map(|line| String::from(self.mac_addr_match.find(line).unwrap().as_str()))
            .collect()

        // for f in &filtered {
        // let m = self.mac_addr_match.find(f).unwrap();
        // println!("{}", m.as_str());
        // }
    }
}
