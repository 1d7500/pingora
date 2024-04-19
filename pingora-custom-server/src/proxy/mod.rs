mod ctx;
mod gateway;
pub(crate) mod load_balancer;
mod modify_response;
mod multi_lb;

pub fn startup_load_balancer() {
    load_balancer::startup();
}
