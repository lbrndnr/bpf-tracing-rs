use anyhow::Result;
use signal_hook::{
    consts::signal::{SIGHUP, SIGINT, SIGTERM},
    iterator::Signals,
};
use tracing_subscriber::filter::LevelFilter;

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_max_level(LevelFilter::TRACE)
        .with_span_events(tracing_subscriber::fmt::format::FmtSpan::FULL)
        .init();

    bpf_tracing::try_init()?;

    let mut signals = Signals::new([SIGINT, SIGHUP, SIGTERM])?;

    for _ in signals.forever() {
        break;
    }

    Ok(())
}
