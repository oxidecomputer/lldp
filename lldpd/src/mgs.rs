use std::net::SocketAddr;

pub async fn detect_switch_slot(
    global: std::sync::Arc<crate::Global>,
    mgs_socket_addr: SocketAddr,
) {
    let url = format!("http://{mgs_socket_addr}");
    let client_log = global.log.new(slog::o!("unit" => "gateway-client"));
    let client = gateway_client::Client::new(&url, client_log);
    let g = global.clone();

    loop {
        // check in with gateway
        let gateway_client::types::SpIdentifier { slot, .. } = match client
            .sp_local_switch_id()
            .await
        {
            Ok(v) => *v,
            Err(e) => {
                slog::error!(g.log, "failed to resolve switch slot"; "error" => %e);
                tokio::time::sleep(tokio::time::Duration::from_secs(10)).await;
                continue;
            }
        };

        slog::info!(g.log, "we are in switch slot {slot}");

        if let Ok(mut ids) = g.switch_identifiers.lock() {
            ids.slot = Some(slot);
        } else {
            slog::error!(
                g.log,
                "failed to obtain lock for updating switch slot"
            );
            continue;
        }
        break;
    }
}
