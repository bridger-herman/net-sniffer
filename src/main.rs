pub mod net_sniffer;

use crate::net_sniffer::NetSniffer;

fn main() {
    let mut ns = NetSniffer::default();

    println!("{:?}", ns.compare_connections());
}
