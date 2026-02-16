use clap::{ArgGroup, Parser};

#[derive(Parser, Debug)]
#[command(name = "probex")]
#[command(about = "eBPF process tracing tool")]
#[command(version)]
#[command(group(
    ArgGroup::new("mode")
        .args(["view", "command"])
        .required(true)
))]
pub struct Args {
    /// Output parquet file (default: trace.parquet)
    #[arg(short, long, default_value = "trace.parquet")]
    pub output: String,

    /// Port for the viewer web interface
    #[arg(short, long, default_value = "8080")]
    pub port: u16,

    /// Don't launch the viewer after tracing
    #[arg(long, conflicts_with = "view")]
    pub no_viewer: bool,

    /// View an existing parquet trace file without tracing a new command
    #[arg(long, value_name = "PARQUET", conflicts_with = "command")]
    pub view: Option<String>,

    /// Perf-style CPU clock sampling frequency (Hz)
    #[arg(long, value_name = "HZ", default_value_t = 999)]
    pub sample_freq: u64,

    /// Command to run
    #[arg(
        trailing_var_arg = true,
        allow_hyphen_values = true,
        required_unless_present = "view"
    )]
    pub command: Vec<String>,
}
