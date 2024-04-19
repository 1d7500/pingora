use arc_swap::ArcSwap;
use async_trait::async_trait;
use log::info;
use pingora::lb::discovery::ServiceDiscovery;
use pingora::lb::Backend;
use pingora::Result;
// use std::thread::{sleep, spawn};
// use std::time::Duration;
use std::{
    collections::{BTreeSet, HashMap},
    sync::Arc,
};

use tokio::time::{self, Duration};

use super::client::EurekaStub;
use std::error::Error;
pub struct EurekaServiceDiscovery {
    service_id: Arc<String>,
    address: Arc<String>,
    backends_cache: Arc<ArcSwap<BTreeSet<Backend>>>,
    stub: EurekaStub,
}

unsafe impl Send for EurekaServiceDiscovery {}

impl EurekaServiceDiscovery {
    pub fn create_and_query(address: &str, service_id: &str) -> Self {
        let address = Arc::new(address.to_owned());
        let service_id = Arc::new(service_id.to_owned());
        let url_prefix = address.clone().to_owned();
        let stub = EurekaStub::new(&url_prefix);

        // let backends = Runtime::new()
        //     .unwrap()
        //     .block_on(async { &self.get_instances(&stub, &service_id).await });

        let backends_cache = Arc::new(ArcSwap::new(Arc::new(BTreeSet::new())));

        let instance = EurekaServiceDiscovery {
            service_id: service_id.clone(),
            address: address.clone(),
            backends_cache: backends_cache.clone(),
            stub: stub,
        };

        instance
    }

    async fn get_instances(&self) -> Result<BTreeSet<Backend>, Box<dyn Error>> {
        let instances = self
            .stub
            .query(&self.service_id)
            .await?
            .into_iter()
            .collect::<BTreeSet<Backend>>();

        info!(
            "service_id: {} instances: {:?}",
            &self.service_id, instances
        );

        Ok(instances)
    }
}

#[async_trait]
impl ServiceDiscovery for EurekaServiceDiscovery {
    async fn discover(&self) -> Result<(BTreeSet<Backend>, HashMap<u64, bool>)> {
        // no readiness
        let backends = self.get_instances().await;
        let health = HashMap::new();

        if backends.is_ok() {
            self.backends_cache.store(Arc::new(backends.ok().unwrap()));
        } else {
            // 查询失败则沿用之前的配置
            info!(
                "load instances failed. address: {} service id: {}",
                self.address, self.service_id
            );
        }

        let snapshot = self.backends_cache.load().clone();

        Ok((BTreeSet::clone(&snapshot), health))
    }
}
