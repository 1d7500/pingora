extern crate pingora_custom_server;

use env_logger::{Builder, Env};
use log::Level;
use std::io::Write;
// #[tokio::main]
fn main() {
    Builder::from_env(Env::default().default_filter_or("info"))
        .format(|buf, record| match record.level() {
            Level::Error => {
                let mut stderr = std::io::stderr();
                writeln!(stderr, "{}: {}", record.level(), record.args())
            }
            _ => {
                writeln!(buf, "{}: {}", record.level(), record.args())
            }
        })
        .init();
    // pingora_custom_server::server::startup();
    // http://192.168.50.2:8761/eureka/apps/BASE-SPRING-WEB
    // 在main中不能在使用tokio，因为在内部启动 Service 的时候有Runtime逻辑，一部分代码实际都是跑在特定Runtime里的
    // 详情可以看 pingora_core::server::Server#run_forever
    pingora_custom_server::proxy::startup_load_balancer();
}
