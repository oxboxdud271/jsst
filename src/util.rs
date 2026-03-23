use std::time::{SystemTime, UNIX_EPOCH};

pub fn get_epoch() -> u64 {
    let now = SystemTime::now();
    match now.duration_since(UNIX_EPOCH) {
        Ok(elapsed) => {
            elapsed.as_secs()
        }
        Err(e) => {
            0
        }
    }
}