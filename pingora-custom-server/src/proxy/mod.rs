mod ctx;
mod gateway;
pub(crate) mod load_balancer;
mod modify_response;

use gateway::StickyConfig;
use std::collections::BTreeMap;

pub fn startup_load_balancer() {
    let mut primary_paths = BTreeMap::new();
    primary_paths.insert(
        "/hello".to_owned(),
        StickyConfig {
            duration_seconds: 30u32,
        },
    );

    load_balancer::startup("http://192.168.50.2:8761", primary_paths);
}
