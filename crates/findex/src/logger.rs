use std::sync::Once;

use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

static LOG_INIT: Once = Once::new();

/// # Panics
///
/// Will panic if we cannot set global tracing subscriber
pub fn log_init() {
    LOG_INIT.call_once(|| {
        tracing_setup();
    });
}

/// # Panics
///
/// Will panic if:
/// - we cannot set global subscriber
/// - we cannot init the log tracer
fn tracing_setup() {
    let format = tracing_subscriber::fmt::layer()
        .with_level(true)
        .with_target(true)
        .with_thread_ids(true)
        .with_line_number(true)
        .with_file(true)
        .with_ansi(true)
        .compact();

    let (filter, _reload_handle) =
        tracing_subscriber::reload::Layer::new(EnvFilter::from_default_env());

    tracing_subscriber::registry()
        .with(filter)
        .with(format)
        .init();
}
