use std::error::Error;
use std::time::{SystemTime, UNIX_EPOCH};
pub type GenericErr<T = (), E = Box<dyn Error>> = Result<T, E>;
pub const BACKUP_BUCKET: &'static str = "jdn-host-backups-048780619790-us-east-1-an";


pub fn get_epoch() -> u64 {
    let now = SystemTime::now();
    match now.duration_since(UNIX_EPOCH) {
        Ok(elapsed) => elapsed.as_secs(),
        Err(_) => 0,
    }
}

pub fn json_to_string(json: &serde_json::Value) -> String {
    String::from(json.as_str().unwrap())
}

pub fn err_if_standalone(opt: &bool) -> GenericErr {
    if *opt {
        return Err("This command is not supported with --standalone (-S)".into());
    }
    Ok(())
}