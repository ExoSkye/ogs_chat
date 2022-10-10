use logger::{Logger, LogDestination, LogSeverity};

mod state;

#[tokio::main]
async fn main() {
    Logger::set_destinations(vec![LogDestination::Stdout, LogDestination::File("server.log".to_string())]);

    Logger::log(LogSeverity::Info, "Server", "Starting server", None);

    let mut config = state::Config::load();

    Logger::log(LogSeverity::Info, "Server", &format!("Peer ID: {}", config.peer_id), None);
}