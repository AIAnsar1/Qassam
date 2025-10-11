use std::{net::TcpStream, time::Duration};






pub fn qassam_zero_byte(buf: &mut [u8]) {
    buf.fill(0)
}


pub fn qassam_set_write_timeout(stream: &TcpStream, timeout: Duration) -> std::io::Result<()> {
    stream.set_write_timeout(Some(timeout))
}


pub fn qassam_set_read_timeout(stream: &TcpStream, timeout: Duration) -> std::io::Result<()> {
    stream.set_read_timeout(Some(timeout))
}


pub fn qassam_get_string_in_between(text: &str, start: &str, end: &str) -> String {
    if let Some(start_pos) = text.find(start) {
        let start_pos = start_pos + start.len();

        if let Some(end_pos) = text[start_pos..].find(end) {
            let end_pos = start_pos + end_pos;
            
            if start_pos > 0 && end_pos > start_pos + 1 {
                return text[start_pos..end_pos].to_string();
            }
        }
    }
    "null".to_string()
}
























