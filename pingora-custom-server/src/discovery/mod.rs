mod eureka;
use eureka::core::EurekaServiceDiscovery;
use pingora::lb::selection::{BackendIter, BackendSelection};
use pingora::lb::Backends;
use pingora::lb::{health_check, LoadBalancer};
use std::sync::Arc;
use std::time::Duration;

pub(crate) fn create_eureka_lb<T: BackendSelection + 'static>(
    address: &str,
    service_id: &str,
) -> (Arc<LoadBalancer<T>>, Arc<LoadBalancer<T>>)
where
    <T as BackendSelection>::Iter: BackendIter,
{
    let factory = |primary| {
        let backends = Backends::new(Box::new(EurekaServiceDiscovery::create(
            address, service_id, primary,
        )));

        let mut lb = LoadBalancer::from_backends(backends);

        lb.set_health_check(health_check::TcpHealthCheck::new());
        lb.health_check_frequency = Some(Duration::from_secs(1));
        lb.update_frequency = Some(Duration::from_secs(5));

        lb
    };

    (Arc::new(factory(true)), Arc::new(factory(false)))
}
