use indexd::app_client::Client;
use log::info;
use rustls_platform_verifier::ConfigVerifierExt;
use sia::objects::{Downloader, HostDialer, Uploader};
use sia::rhp::quic::Dialer;
use sia::signing::PrivateKey;
use sia::types::Hash256;
use std::env;
use std::time::Instant;
use tokio::fs::File;

#[tokio::main]
async fn main() {
    const SECRET: &str = "hello, world!";

    pretty_env_logger::init();
    let input_path = env::args().nth(1).expect("no input_path given");
    let output_path = env::args().nth(2).expect("no output_path given");

    let h: Hash256 = blake2b_simd::Params::new()
        .hash_length(32)
        .to_state()
        .update(SECRET.as_bytes())
        .finalize()
        .into();

    let private_key = PrivateKey::from_seed(h.as_ref());
    let client = Client::new("https://app.indexd.zeus.sia.dev", private_key.clone())
        .expect("failed to create client");

    /*let connect_response = client.request_app_connection(&RegisterAppRequest{
        name: "upload-rs".into(),
        description: Some("A tool for uploading files to Sia via indexd".into()),
        logo_url: Some("https://foo.bar".parse().unwrap()),
        service_url: "https://foo.bar".parse().unwrap(),
        callback_url: None,
    }).await.expect("failed to register app");

    info!("Go to {} to approve app", connect_response.response_url);
    info!("Waiting for approval...");
    while !client.check_request_status(connect_response.status_url.parse().unwrap()).await.expect("failed to check status") {
        tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
    }
    info!("App has been approved!");*/

    if rustls::crypto::CryptoProvider::get_default().is_none() {
        rustls::crypto::ring::default_provider()
            .install_default()
            .unwrap();
    }

    let client_config =
        rustls::ClientConfig::with_platform_verifier().expect("Failed to create client config");

    let mut dialer = Dialer::new(client_config).expect("Failed to create dialer");
    dialer.update_hosts(client.hosts().await.expect("Failed to get hosts"));
    info!("initialized dialer with {} hosts", dialer.hosts().len());

    //info!("waiting 60s for host funding");
    //sleep(Duration::from_secs(60)).await; // wait for host funding

    let uploader = Uploader::new(dialer.clone(), private_key.clone(), 5);

    let input = File::open(input_path).await.expect("failed to open file");
    let encryption_key = rand::random();
    info!("uploading file");
    let start = Instant::now();
    let slabs = uploader
        .upload(input, encryption_key, 10, 20)
        .await
        .expect("failed to upload file");
    info!(
        "upload {} complete in {}ms",
        slabs[0].length,
        start.elapsed().as_millis()
    );

    info!("downloading file");
    let mut output = File::create(output_path)
        .await
        .expect("failed to create file");
    let start = Instant::now();
    let downloader = Downloader::new(dialer.clone(), private_key.clone(), 30);
    downloader
        .download(&mut output, &slabs)
        .await
        .expect("failed to download file");
    info!("download complete in {}ms", start.elapsed().as_millis());
}
