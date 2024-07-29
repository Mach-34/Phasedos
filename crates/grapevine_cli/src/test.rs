use assert_cmd::Command;
use grapevine_common::errors::GrapevineError;
use std::path::Path;

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;

    fn grapevine_dir() -> Result<PathBuf, GrapevineError> {
        match std::env::var("HOME") {
            Ok(home) => Ok(Path::new(&home).join(".grapevine")),
            Err(_) => {
                return Err(GrapevineError::FsError(String::from(
                    "Couldn't find home directory??",
                )))
            }
        }
    }

    // move safe.key back into grapevine.key
    fn restore_key(grapevine_dir: &PathBuf) {
        Command::new("mv")
            .current_dir(grapevine_dir)
            .args(&["real.key", "grapevine.key"])
            .assert()
            .success();
    }

    // move grapevine.key for testing
    fn move_key(grapevine_dir: &PathBuf) {
        Command::new("mv")
            .current_dir(grapevine_dir)
            .args(&["grapevine.key", "real.key"])
            .assert()
            .success();
    }

    #[test]
    fn test_no_account() {
        // load in grapevine dir
        let grapevine_dir = grapevine_dir().unwrap();
        // move grapevine.key
        move_key(&grapevine_dir);

        // call account info with no grapevine.key file
        let output = Command::new("grapevine")
            .arg("account")
            .arg("info")
            .output()
            .unwrap();
        println!("Output: {:?}", output);

        // restore grapevine.key
        // restore_key(&grapevine_dir);
    }
}
