use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    sync::Arc,
};

use maxminddb::{geoip2, Reader};

use axum::{
    extract::{ConnectInfo, State},
    http::{self, Request},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::get,
    Router,
};
use serde::{Deserialize, Serialize};

fn get_asn(reader: &Reader<Vec<u8>>, ip: IpAddr) -> Option<u32> {
    let (isp, _) = reader.lookup_prefix::<geoip2::Isp>(ip).unwrap();

    isp.autonomous_system_number
}

async fn my_middleware<B>(
    State(state): State<Arc<AppState>>,
    request: Request<B>,
    next: Next<B>,
) -> Response {
    let request_addr = request.extensions().get::<ConnectInfo<SocketAddr>>();
    // todo: check for x-forwarded-for header (CF support)

    match request_addr {
        Some(ConnectInfo(addr)) => {
            let ip = addr.ip();
            let asn = get_asn(&state.mmdb, ip);

            match asn {
                Some(asn) => {
                    let asn = asn.to_string();

                    let is_blocked = match state.asn_list.get(&asn) {
                        Some(asn) => (true, asn.name.clone()),
                        None => (false, "".to_string()),
                    };

                    if is_blocked.0 {
                        return (
                            http::StatusCode::FORBIDDEN,
                            format!(
                                "Your ISP {} ({}) has been blocked from this website",
                                asn, is_blocked.1
                            ),
                        )
                            .into_response();
                    }
                    next.run(request).await
                }
                None => return next.run(request).await,
            }
        }
        None => return next.run(request).await,
    }
}

#[derive(Serialize, Deserialize)]
struct ASNVal {
    #[serde(rename = "entity")]
    name: String,
}

struct AppState {
    mmdb: Reader<Vec<u8>>,
    asn_list: HashMap<String, ASNVal>,
}

#[tokio::main]
async fn main() {
    let json = std::fs::read_to_string("./deps/bad_asn.json").unwrap();
    let asn_list = serde_json::from_str::<HashMap<String, ASNVal>>(&json).unwrap();

    let state = Arc::new(AppState {
        mmdb: Reader::open_readfile("./deps/GeoLite2-ASN.mmdb").unwrap(),
        asn_list,
    });

    let app = Router::new()
        .route("/", get(|| async { "Hello, World!" }))
        .layer(middleware::from_fn_with_state(state.clone(), my_middleware))
        .with_state(state);

    axum::Server::bind(&"0.0.0.0:3000".parse().unwrap())
        .serve(app.into_make_service_with_connect_info::<SocketAddr>())
        .await
        .unwrap();
}
