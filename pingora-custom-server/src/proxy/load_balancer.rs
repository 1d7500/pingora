// Copyright 2024 Cloudflare, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use async_trait::async_trait;
use log::info;
use pingora::services::background::background_service;
use pingora::services::Service;
use std::collections::BTreeMap;
use std::sync::Arc;
use structopt::StructOpt;

use crate::discovery;
use crate::proxy::gateway::{Router, StickyConfig};

use pingora::lb::{selection::RoundRobin, LoadBalancer};
use pingora::proxy::{ProxyHttp, Session};
use pingora::server::configuration::Opt;
use pingora::server::Server;
use pingora::upstreams::peer::HttpPeer;
use pingora::Result;

use tokio::sync::watch;

// pub struct LB(Arc<LoadBalancer<RoundRobin>>);

// #[async_trait]
// impl ProxyHttp for LB {
//     type CTX = ();
//     fn new_ctx(&self) -> Self::CTX {}

//     async fn upstream_peer(&self, _session: &mut Session, _ctx: &mut ()) -> Result<Box<HttpPeer>> {
//         let upstream = self
//             .0
//             .select(b"", 256) // hash doesn't matter
//             .unwrap();

//         info!("upstream peer is: {:?}", upstream);

//         let peer = Box::new(HttpPeer::new(
//             upstream,
//             false,
//             "one.one.one.one".to_string(),
//         ));
//         Ok(peer)
//     }

//     async fn upstream_request_filter(
//         &self,
//         _session: &mut Session,
//         upstream_request: &mut pingora::http::RequestHeader,
//         _ctx: &mut Self::CTX,
//     ) -> Result<()> {
//         upstream_request
//             .insert_header("Host", "one.one.one.one")
//             .unwrap();
//         Ok(())
//     }
// }

// RUST_LOG=INFO cargo run --example load_balancer
pub fn startup(registry_address: &str, primary_paths: BTreeMap<String, StickyConfig>) {
    //
    // read command line arguments
    let (tx, mut rx): (watch::Sender<bool>, watch::Receiver<bool>) = watch::channel(false);

    let opt = Opt::from_args();
    let mut my_server = Server::new(Some(opt)).unwrap();
    my_server.bootstrap();

    let (primary_upstreams, full_upstreams) =
        crate::discovery::create_eureka_lb(registry_address, "BASE-SPRING-WEB");

    let router = Router::new(
        primary_paths,
        primary_upstreams.clone(),
        full_upstreams.clone(),
    );

    let background_full = background_service("health check", full_upstreams.clone());
    let background_primary = background_service("health check", primary_upstreams.clone());

    let _ = background_full.task();
    let _ = background_primary.task();

    let mut lb = pingora::proxy::http_proxy_service(&my_server.configuration, router);
    lb.add_tcp("0.0.0.0:6188");
    // lb.add_tls_with_settings("0.0.0.0:6189", None, get_tls_settings());

    my_server.add_service(lb);
    my_server.add_service(background_full);
    my_server.add_service(background_primary);
    my_server.run_forever();
}

// TODO 单独追加方法?

fn get_tls_settings() -> pingora::listeners::TlsSettings {
    let cert_path = format!("{}/tests/keys/server.crt", env!("CARGO_MANIFEST_DIR"));
    let key_path = format!("{}/tests/keys/key.pem", env!("CARGO_MANIFEST_DIR"));

    let mut tls_settings =
        pingora::listeners::TlsSettings::intermediate(&cert_path, &key_path).unwrap();
    tls_settings.enable_h2();

    tls_settings
}
