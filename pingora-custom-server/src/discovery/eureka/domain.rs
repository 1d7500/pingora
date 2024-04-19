use pingora::lb::Backend;
use pingora::Result;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub(in crate::discovery::eureka) struct Application {
    name: String,
    pub(in crate::discovery::eureka) instance: Vec<Instance>,
}

#[derive(Debug, Serialize, Deserialize)]
pub(in crate::discovery::eureka) struct Applications {
    pub application: Application,
}

#[derive(Debug, Serialize, Deserialize)]
pub(in crate::discovery::eureka) struct AllApplications {
    applications: Applications,
}

#[derive(Serialize, Deserialize, Debug)]
struct Port {
    #[serde(rename = "$")]
    port: u16,
    #[serde(rename = "@enabled")]
    enabled: String,
}
#[derive(Debug, Serialize, Deserialize)]
pub(in crate::discovery::eureka) struct Instance {
    instanceId: String,
    hostName: String,
    app: String,
    ipAddr: String,
    port: Option<Port>,
    securePort: Option<Port>,
    status: String,
}

impl Instance {
    pub fn create_backend(&self) -> Result<Backend> {
        let url_prefix = if let Some(p) = &self.port {
            format!("{}:{}", &self.ipAddr, p.port)
        } else {
            self.ipAddr.to_owned()
        };

        Backend::new(&url_prefix)
    }
}
