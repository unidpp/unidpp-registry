//! Entrypoint: environment-driven configuration, then serve forever.

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let config = unidpp_registry::Config::from_env();
    unidpp_registry::run(config).await
}
