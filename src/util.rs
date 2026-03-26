use std::time::{SystemTime, UNIX_EPOCH};

pub fn get_epoch() -> u64 {
    let now = SystemTime::now();
    match now.duration_since(UNIX_EPOCH) {
        Ok(elapsed) => elapsed.as_secs(),
        Err(_) => 0,
    }
}

pub fn json_to_string(json: serde_json::Value) -> String {
    String::from(json.as_str().unwrap())
}