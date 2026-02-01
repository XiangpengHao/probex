//! Snitch Trace Viewer
//!
//! A web-based visualization tool for snitch parquet trace files.
//! Uses Dioxus fullstack with DataFusion for efficient querying.

use dioxus::prelude::*;

mod server;
mod ui;

const FAVICON: Asset = asset!("/assets/favicon.ico");
const TAILWIND_CSS: Asset = asset!("/assets/tailwind.css");

#[cfg(feature = "server")]
mod cli {
    use clap::Parser;

    #[derive(Parser, Debug)]
    #[command(name = "snitch-viewer")]
    #[command(about = "Web-based visualization for snitch trace files")]
    #[command(version)]
    pub struct Args {
        /// Parquet trace file to visualize (or set SNITCH_FILE env var)
        #[arg(short, long, env = "SNITCH_FILE")]
        pub file: String,

        /// Port to listen on
        #[arg(short, long, default_value = "8080")]
        pub port: u16,

        /// Address to bind to
        #[arg(short, long, default_value = "0.0.0.0")]
        pub address: String,
    }
}

fn main() {
    #[cfg(feature = "server")]
    {
        use clap::Parser;
        
        env_logger::init();

        let args = cli::Args::parse();

        let parquet_path = std::path::PathBuf::from(&args.file);
        if !parquet_path.exists() {
            eprintln!("Error: Parquet file not found: {}", args.file);
            std::process::exit(1);
        }

        server::set_parquet_file(parquet_path.clone());

        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            if let Err(e) = server::init_datafusion().await {
                eprintln!("Failed to initialize DataFusion: {}", e);
                eprintln!("Make sure the parquet file is valid: {:?}", parquet_path);
                std::process::exit(1);
            }
        });
    }

    dioxus::launch(ui::App);
}
