mod state;

use libp2p::*;

#[tokio::main]
async fn main() {
    let mut config = state::Config::load();

    println!("Peer ID: {}", config.peer_id);
}