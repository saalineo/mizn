use super::SmtpConfig;
use hyper::header::CONTENT_TYPE;
use hyper::{Body, Client, Request, StatusCode};
use hyper_tls::HttpsConnector;
use std::time::Duration;

const WEBHOOK_TIMEOUT: Duration = Duration::from_secs(10);

fn webhook_payload(level: &str, message: &str) -> String {
    serde_json::json!({
        "text": format!("[MIZN][{}] {}", level, message),
    })
    .to_string()
}

pub async fn dispatch_webhook(url: &str, level: &str, message: &str) {
    let payload = webhook_payload(level, message);
    eprintln!("[miznd][alert][webhook] → {}", payload);

    let request = match Request::post(url)
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(payload))
    {
        Ok(request) => request,
        Err(error) => {
            eprintln!("[miznd][alert][webhook] invalid URL {}: {}", url, error);
            return;
        }
    };

    let client = Client::builder().build::<_, Body>(HttpsConnector::new());
    match tokio::time::timeout(WEBHOOK_TIMEOUT, client.request(request)).await {
        Ok(Ok(response)) if response.status().is_success() => {
            eprintln!(
                "[miznd][alert][webhook] posted to {} ({})",
                url,
                response.status()
            );
        }
        Ok(Ok(response)) => {
            let status: StatusCode = response.status();
            eprintln!(
                "[miznd][alert][webhook] POST to {} failed with {}",
                url, status
            );
        }
        Ok(Err(error)) => {
            eprintln!("[miznd][alert][webhook] POST to {} failed: {}", url, error);
        }
        Err(_) => {
            eprintln!(
                "[miznd][alert][webhook] POST to {} timed out after {}s",
                url,
                WEBHOOK_TIMEOUT.as_secs()
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::webhook_payload;

    #[test]
    fn webhook_payload_escapes_message_as_json() {
        let payload = webhook_payload("Warning", "quote: \" and newline:\n");
        let value: serde_json::Value = serde_json::from_str(&payload).unwrap();

        assert_eq!(value["text"], "[MIZN][Warning] quote: \" and newline:\n");
    }
}

pub async fn dispatch_smtp(smtp: &SmtpConfig, message: &str) {
    let smtp = smtp.clone();
    let message = message.to_owned();
    let result = tokio::task::spawn_blocking(move || send_smtp(smtp, message)).await;

    if let Err(error) = result {
        eprintln!("[miznd][smtp] Send task failed: {}", error);
    }
}

fn send_smtp(smtp: SmtpConfig, message: String) {
    use lettre::message::header::ContentType;
    use lettre::transport::smtp::authentication::Credentials;
    use lettre::{Message, SmtpTransport, Transport};

    let email_result = Message::builder()
        .from(
            smtp.from
                .parse()
                .unwrap_or_else(|_| "mizn@localhost".parse().unwrap()),
        )
        .to(smtp
            .to
            .parse()
            .unwrap_or_else(|_| "admin@localhost".parse().unwrap()))
        .subject("[MIZN ALERT] Security event detected")
        .header(ContentType::TEXT_PLAIN)
        .body(message);

    let email = match email_result {
        Ok(e) => e,
        Err(e) => {
            eprintln!("[miznd][smtp] message build error: {}", e);
            return;
        }
    };

    let creds = Credentials::new(smtp.username.clone(), smtp.password.clone());
    let mailer = SmtpTransport::relay(&smtp.relay).map(|b| b.credentials(creds).build());

    match mailer {
        Ok(m) => match m.send(&email) {
            Ok(_) => eprintln!("[miznd][smtp] Alert sent to {}", smtp.to),
            Err(e) => eprintln!("[miznd][smtp] Send error: {}", e),
        },
        Err(e) => eprintln!("[miznd][smtp] Relay error: {}", e),
    }
}
