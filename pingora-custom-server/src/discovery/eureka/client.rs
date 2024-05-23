use crate::discovery::eureka::domain::Applications;
use pingora::lb::Backend;
use std::error::Error;

pub(in crate::discovery::eureka) struct EurekaStub {
    url_prefix: String,
    client: reqwest::Client,
}

// http://192.168.50.2:8761/eureka/apps/BASE-SPRING-WEB

impl EurekaStub {
    pub(in crate::discovery::eureka) fn new(url_prefix: &str) -> Self {
        EurekaStub {
            url_prefix: url_prefix.to_owned(),
            client: reqwest::Client::new(),
        }
    }

    pub(in crate::discovery::eureka) async fn query(
        &self,
        application_name: &str,
        primary: bool,
    ) -> Result<Vec<Backend>, Box<dyn Error>> {
        let url = format!("{}/eureka/apps/{}", &self.url_prefix, application_name);

        let response = self
            .client
            .get(&url)
            .header("Accept", "application/json")
            .header("Content-Type", "application/json")
            .send()
            .await?;

        let body = response.text().await?;
        let response = serde_json::from_str::<Applications>(&body)?;

        let mut backends = response
            .application
            .instance
            .iter()
            .filter_map(|instance| instance.create_backend().ok());

        let backends = if primary {
            backends.filter(|backend| backend.primary == true).collect()
        } else {
            backends.collect()
        };

        // use log::info;
        // info!("primary: {} backends: {:?}", primary, backends);

        Ok(backends)
    }
}
