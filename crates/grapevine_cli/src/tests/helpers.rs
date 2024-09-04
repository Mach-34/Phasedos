use assert_cmd::{output, Command};
use grapevine_common::errors::GrapevineError;
use std::path::{Path, PathBuf};

pub fn account_info_cmd() -> String {
    let bytes = Command::new("grapevine")
        .arg("account")
        .arg("info")
        .output()
        .unwrap()
        .stdout;
    String::from_utf8(bytes).unwrap()
}

pub fn add_relationship_cmd(recipient: &str) -> String {
    let bytes = Command::new("grapevine")
        .arg("relationship")
        .arg("add")
        .arg(recipient)
        .output()
        .unwrap()
        .stdout;
    String::from_utf8(bytes).unwrap()
}

pub fn create_account_cmd(username: &str) -> String {
    let bytes = Command::new("grapevine")
        .arg("account")
        .arg("register")
        .arg(username)
        .output()
        .unwrap()
        .stdout;
    String::from_utf8(bytes).unwrap()
}

pub fn list_active_relationships_cmd() -> String {
    let bytes = Command::new("grapevine")
        .arg("relationship")
        .arg("list")
        .output()
        .unwrap()
        .stdout;
    String::from_utf8(bytes).unwrap()
}

pub fn list_pending_relationships_cmd() -> String {
    let bytes = Command::new("grapevine")
        .arg("relationship")
        .arg("pending")
        .output()
        .unwrap()
        .stdout;
    String::from_utf8(bytes).unwrap()
}

pub fn get_scope_cmd(username: &str) -> String {
    let bytes = Command::new("grapevine")
        .arg("proof")
        .arg("scope")
        .arg(username)
        .output();
    println!("Output: {:?}", bytes);
    // .unwrap()
    // .stdout;
    // String::from_utf8(bytes).unwrap()
    String::from("")
}

pub fn reject_relationship_cmd(username: &str) -> String {
    let bytes = Command::new("grapevine")
        .arg("relationship")
        .arg("reject")
        .arg(username)
        .output()
        .unwrap()
        .stdout;
    String::from_utf8(bytes).unwrap()
}

pub fn remove_relationship_cmd(username: &str) -> String {
    let bytes = Command::new("grapevine")
        .arg("relationship")
        .arg("remove")
        .arg(username)
        .output()
        .unwrap()
        .stdout;
    String::from_utf8(bytes).unwrap()
}

pub fn grapevine_dir() -> Result<PathBuf, GrapevineError> {
    match std::env::var("HOME") {
        Ok(home) => Ok(Path::new(&home).join(".grapevine")),
        Err(_) => {
            return Err(GrapevineError::FsError(String::from(
                "Couldn't find home directory??",
            )))
        }
    }
}

pub fn remove_file(grapevine_dir: &PathBuf, file_name: &str) {
    Command::new("rm")
        .current_dir(grapevine_dir)
        .arg(file_name)
        .assert()
        .success();
}

pub fn rename_file(grapevine_dir: &PathBuf, old_name: &str, new_name: &str) {
    Command::new("mv")
        .current_dir(grapevine_dir)
        .args(&[old_name, new_name])
        .assert()
        .success();
}

// move safe.key back into grapevine.key
pub fn restore_key(grapevine_dir: &PathBuf) {
    Command::new("mv")
        .current_dir(grapevine_dir)
        .args(&["real.key", "grapevine.key"])
        .assert()
        .success();
}

// move grapevine.key for testing
pub fn move_key(grapevine_dir: &PathBuf) {
    Command::new("mv")
        .current_dir(grapevine_dir)
        .args(&["grapevine.key", "real.key"])
        .assert()
        .success();
}
