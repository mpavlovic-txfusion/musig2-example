use clap::Parser;
use musig2_example::SignerNode;
use std::error::Error;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(long)]
    port: u16,

    #[arg(long)]
    peers: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::parse();
    let discovery_ports: Vec<u16> = args
        .peers
        .split(',')
        .filter_map(|s| s.trim().parse().ok())
        .collect();

    let signer = SignerNode::new(args.port, discovery_ports);
    println!("🔑 Starting signer node...");
    signer.start().await
}
