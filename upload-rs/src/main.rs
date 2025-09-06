use indexd::{Error, SDK};
use log::info;
use sia::signing::PrivateKey;
use sia::types::Hash256;
use std::env;
use std::time::Instant;
use tokio::fs::File;

#[tokio::main]
async fn main() -> Result<(), Error> {
    const APP_URL: &str = "https://app.indexd.zeus.sia.dev";
    const SECRET: &str = "supersecret";

    pretty_env_logger::init();

    let input_path = env::args().nth(1).expect("no input_path given");
    let output_path = env::args().nth(2).expect("no output_path given");

    let h: Hash256 = blake2b_simd::Params::new()
        .hash_length(32)
        .to_state()
        .update(SECRET.as_bytes())
        .finalize()
        .into();
    let app_key = PrivateKey::from_seed(h.as_ref());

    let sdk = SDK::connect(
        APP_URL,
        app_key,
        "upload-rs".into(),
        "A simple upload tool ".into(),
        "https://foo.bar".parse().unwrap(),
    )
    .await?;

    if sdk.needs_approval() {
        info!("approve the app at: {}", sdk.approval_url().unwrap());
    }

    let sdk = sdk.connected(None).await?;
    info!("app connected");

    info!("uploading file");
    let input = File::open(input_path).await.expect("failed to open input");
    let encryption_key: [u8; 32] = rand::random();
    let mut start = Instant::now();
    let slabs = sdk.upload(input, encryption_key, 10, 20).await?;
    info!(
        "upload {} complete in {}ms",
        slabs[0].length,
        start.elapsed().as_millis()
    );

    info!("downloading file");
    let mut output = File::create(output_path)
        .await
        .expect("failed to create output");
    start = Instant::now();
    sdk.download(&mut output, &slabs).await?;
    info!("download complete in {}ms", start.elapsed().as_millis());

    Ok(())
}
