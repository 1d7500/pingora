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
use http::header::{COOKIE, SET_COOKIE};
use std::ops::Bound;
use std::sync::Arc;

use chrono::prelude::*;
use log::info;
use pingora::http::ResponseHeader;
use pingora::lb::{
    health_check::TcpHealthCheck,
    selection::{BackendIter, BackendSelection, RoundRobin},
    LoadBalancer,
};
use pingora::proxy::{http_proxy_service, ProxyHttp, Session};
use pingora::{prelude::*, services::background::GenBackgroundService};

use std::collections::BTreeMap;

const HEADER_STICKINESS_KEY: &'static str = "Stickiness-Primary";

#[derive(Debug)]
pub(crate) struct StickyConfig {
    pub duration_seconds: u32,
}

#[derive(Debug)]
pub(crate) struct SessionCtx {
    stickiness_state: StickinessState,
    stickiness_expired: i64,
}

pub(crate) struct Router {
    primary_paths: BTreeMap<String, StickyConfig>,
    primary_cluster: Arc<LoadBalancer<RoundRobin>>,
    full_cluster: Arc<LoadBalancer<RoundRobin>>,
}

impl Router {
    pub(crate) fn new(
        primary_paths: BTreeMap<String, StickyConfig>,
        primary_cluster: Arc<LoadBalancer<RoundRobin>>,
        full_cluster: Arc<LoadBalancer<RoundRobin>>,
    ) -> Self {
        Router {
            primary_paths: primary_paths,
            primary_cluster: primary_cluster,
            full_cluster: full_cluster,
        }
    }
}

#[derive(Debug, PartialEq)]
enum StickinessState {
    None,
    New,
    Continue,
}

#[async_trait]
impl ProxyHttp for Router {
    type CTX = SessionCtx;
    fn new_ctx(&self) -> SessionCtx {
        SessionCtx {
            stickiness_state: StickinessState::None,
            stickiness_expired: -1,
        }
    }

    async fn upstream_peer(
        &self,
        session: &mut Session,
        _ctx: &mut SessionCtx,
    ) -> Result<Box<HttpPeer>> {
        // 此处应该有个TreeMap 来识别是否是必须走主节点的逻辑

        let path = session.req_header().uri.path().to_owned();
        let now = Utc::now().timestamp();

        info!(
            "received request. path: {} primary_paths: {:?}",
            path,
            self.primary_paths
                .upper_bound(Bound::Included(&path))
                .peek_prev()
        );

        let mut expired = -1i64;

        let cookies = session
            .req_header()
            .headers
            .get_all(COOKIE)
            .into_iter()
            .collect::<Vec<_>>(); // TODO 可以转换为Map

        for cookie in cookies {
            let value = cookie.to_str().ok().unwrap();
            if value.starts_with(HEADER_STICKINESS_KEY) {
                if let Some((_, value)) = value.split_once("=") {
                    expired = value.parse::<i64>().ok().unwrap();
                }
            }
        }

        if let Some((epath, config)) = self
            .primary_paths
            .upper_bound(Bound::Included(&path))
            .peek_prev()
            && path.starts_with(epath)
        {
            info!("use primary_cluster[path]. path: {}", path);

            _ctx.stickiness_state = StickinessState::New;
            _ctx.stickiness_expired = now + config.duration_seconds as i64; // TODO 这里应该直接用 duration_seconds 替换，用来设置Cookie的 age
        } else if expired > 0 {
            if now > expired {
                info!("stickiness header is expired. path: {}", path);
                _ctx.stickiness_state = StickinessState::None;
            } else {
                info!("use primary_cluster[stickiness]. path: {}", path);
                _ctx.stickiness_state = StickinessState::Continue;
            }
        } else {
            info!("use full_cluster[stickiness]. path: {}", path);
        }

        let cluster = match _ctx.stickiness_state {
            StickinessState::None => &self.full_cluster,
            _ => &self.primary_cluster,
        };

        let upstream = cluster
            .select(b"", 256) // hash doesn't matter for round robin
            .unwrap();

        // Set SNI to one.one.one.one
        let peer = Box::new(HttpPeer::new(
            upstream,
            false,
            "one.one.one.one".to_string(),
        ));
        Ok(peer)
    }

    fn upstream_response_filter(
        &self,
        _session: &mut Session,
        _upstream_response: &mut ResponseHeader,
        _ctx: &mut Self::CTX,
    ) {
        if _ctx.stickiness_state == StickinessState::New {
            let value = format!(
                // "{}={}; Path=/; Max-Age=900; HttpOnly; Secure", // 没有HTTPS所以暂时不设置Secure，另外也不能设置 Domain
                "{}={}; Max-Age=900; HttpOnly;",
                HEADER_STICKINESS_KEY, _ctx.stickiness_expired
            );

            _upstream_response.append_header(SET_COOKIE, value);
        }
    }
}
