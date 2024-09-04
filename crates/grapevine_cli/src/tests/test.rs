use crate::http::reset_db;
use crate::tests::helpers::{
    account_info_cmd, create_account_cmd, grapevine_dir, move_key, restore_key,
};
use assert_cmd::Command;

// These tests assume user has not changed their file system

#[cfg(test)]
mod account_tests {
    use super::*;
    use crate::controllers::{get_account, make_or_get_account};

    #[test]
    #[ignore]
    fn test_no_server_connection() {
        todo!("Unimplemented");
    }

    #[test]
    fn test_no_keyfile() {
        // load in grapevine dir
        let grapevine_dir = grapevine_dir().unwrap();
        // move grapevine.key
        move_key(&grapevine_dir);

        // call account info with no grapevine.key file
        let output = account_info_cmd();
        assert!(
            output.contains("Filesystem error: No Grapevine account found"),
            "No account should be found."
        );

        // restore grapevine.key
        restore_key(&grapevine_dir);
    }

    #[test]
    #[ignore]
    fn test_nonexistent_account() {
        // load in grapevine dir
        let grapevine_dir = grapevine_dir().unwrap();
        // move grapevine.key
        move_key(&grapevine_dir);

        // create new account locally
        let username = String::from("local_account");
        _ = make_or_get_account(username);

        // call account info command with no account created
        let output = Command::new("grapevine")
            .arg("account")
            .arg("info")
            .output();

        println!("Output: {:?}", output);
    }

    #[test]
    fn test_register_account_username_too_long() {
        // load in grapevine dir
        let grapevine_dir = grapevine_dir().unwrap();
        // move grapevine.key
        move_key(&grapevine_dir);

        let username = String::from("account_that_exceeds_thirty_characters");

        // create account
        let output = create_account_cmd(&username);

        let expected_output =
            "Error: Username account_that_exceeds_thirty_characters is too long\n";

        assert_eq!(output, expected_output);

        // restore grapevine.key
        restore_key(&grapevine_dir);
    }

    #[test]
    fn test_register_account_non_ascii_characters() {
        // load in grapevine dir
        let grapevine_dir = grapevine_dir().unwrap();
        // move grapevine.key
        move_key(&grapevine_dir);

        let username = String::from("account_with_🤪😎😏");

        // create account
        let output = create_account_cmd(&username);

        let expected_output = "Error: Username account_with_🤪😎😏 is not ascii\n";

        assert_eq!(output, expected_output);

        // restore grapevine.key
        restore_key(&grapevine_dir);
    }

    #[tokio::test]
    async fn test_register_account() {
        // clear db
        reset_db().await;
        // load in grapevine dir
        let grapevine_dir = grapevine_dir().unwrap();
        // move grapevine.key
        move_key(&grapevine_dir);

        let username = String::from("valid_username");

        // create account
        let output = create_account_cmd(&username);

        let expected_output = format!("Created Grapevine account at /Users/ianbrighton/.grapevine/grapevine.key\nSuccess: registered account for \"{}\"\n", username);

        assert_eq!(output, expected_output);

        // restore grapevine.key
        restore_key(&grapevine_dir);
    }

    #[tokio::test]
    async fn test_register_account_duplicate() {
        // clear db
        reset_db().await;
        // load in grapevine dir
        let grapevine_dir = grapevine_dir().unwrap();
        // move grapevine.key
        move_key(&grapevine_dir);

        let username = String::from("duplicate_user");

        // create account
        let _ = create_account_cmd(&username);

        // create account with same username
        let output = create_account_cmd(&username);
        let expected_output = format!(
            "Error: User {} already exists with the supplied pubkey\n",
            username
        );

        assert_eq!(output, expected_output);

        // restore grapevine.key
        restore_key(&grapevine_dir);
    }

    #[tokio::test]
    async fn test_account_info() {
        // clear db
        reset_db().await;
        // load in grapevine dir
        let grapevine_dir = grapevine_dir().unwrap();
        // move grapevine.key
        move_key(&grapevine_dir);

        let username = String::from("valid_username");

        // create account
        _ = create_account_cmd(&username);

        let output = account_info_cmd();
        let account = get_account().unwrap();
        let pubkey = format!("0x{}", hex::encode(account.pubkey().compress()));
        let expected_output = format!("Username: {}\nPublic key: {}\n# 1st degree connections: 0\n# 2nd degree connections: 0\n\n", username, pubkey);

        assert_eq!(expected_output, output);

        // restore grapevine.key
        restore_key(&grapevine_dir);
    }

    #[tokio::test]
    async fn test_account_export() {
        // clear db
        reset_db().await;
        // load in grapevine dir
        let grapevine_dir = grapevine_dir().unwrap();
        // move grapevine.key
        move_key(&grapevine_dir);

        let username = String::from("export_username");

        // create account
        _ = create_account_cmd(&username);

        let bytes = Command::new("grapevine")
            .arg("account")
            .arg("export")
            .output()
            .unwrap()
            .stdout;
        let output = String::from_utf8(bytes).unwrap();

        let account = get_account().unwrap();
        let privkey = format!("0x{}", hex::encode(account.private_key_raw()));
        let expected_output = format!(
            "Sensitive account details for {}:\nPrivate Key: {}\n",
            username, privkey
        );

        assert_eq!(output, expected_output);

        // restore grapevine.key
        restore_key(&grapevine_dir);
    }
}

#[cfg(test)]
mod health_tests {
    #[ignore]
    #[test]
    fn test_healthcheck() {
        todo!("Unimplemented")
    }
}

#[cfg(test)]
mod proof_tests {
    use crate::tests::helpers::get_scope_cmd;

    use super::*;

    #[ignore]
    #[tokio::test]
    async fn test_scope_user_not_found() {
        // clear db
        reset_db().await;
        // load in grapevine dir
        let grapevine_dir = grapevine_dir().unwrap();
        // move grapevine.key
        move_key(&grapevine_dir);

        let username = String::from("user_a");

        // create accounts
        _ = create_account_cmd(&username);

        let output = get_scope_cmd("fake_user");
        println!("Output: {:?}", output);

        // restore grapevine.key
        restore_key(&grapevine_dir);
    }

    #[ignore]
    #[test]
    fn test_scope_degree_not_found() {
        todo!("Unimplemented");
    }

    #[ignore]
    #[test]
    fn test_scope() {
        todo!("Unimplemented");
    }

    #[ignore]
    #[test]
    fn test_sync_degrees_no_available_degrees() {
        todo!("Unimplemented");
    }

    #[ignore]
    #[test]
    fn test_sync_degrees() {
        todo!("Unimplemented");
    }

    #[ignore]
    #[test]
    fn test_list_available_none() {
        todo!("Unimplemented");
    }

    #[ignore]
    #[test]
    fn test_list_available() {
        todo!("Unimplemented");
    }
}

#[cfg(test)]
mod relationship_tests {

    use crate::tests::helpers::{
        add_relationship_cmd, list_active_relationships_cmd, list_pending_relationships_cmd,
        reject_relationship_cmd, remove_file, remove_relationship_cmd, rename_file,
    };

    use super::*;

    #[tokio::test]
    async fn test_add_relationship_nonexistent_recipient() {
        // clear db
        reset_db().await;
        // load in grapevine dir
        let grapevine_dir = grapevine_dir().unwrap();
        // move grapevine.key
        move_key(&grapevine_dir);

        let username = String::from("user_a");
        let username_b = String::from("fake_user");

        // create accounts
        _ = create_account_cmd(&username);

        let output = add_relationship_cmd(&username_b);
        let expected_ouput = format!("Error: Username {} does not exist\n", username_b);

        assert_eq!(expected_ouput, output);

        // restore grapevine.key
        restore_key(&grapevine_dir);
    }

    #[tokio::test]
    async fn test_add_relationship_sender_is_recipient() {
        // clear db
        reset_db().await;
        // load in grapevine dir
        let grapevine_dir = grapevine_dir().unwrap();
        // move grapevine.key
        move_key(&grapevine_dir);

        let username = String::from("user_a");

        // create accounts
        _ = create_account_cmd(&username);

        let output = add_relationship_cmd(&username);
        let expected_ouput = "Error: Relationship sender and target are the same\n";

        assert_eq!(expected_ouput, output);

        // restore grapevine.key
        restore_key(&grapevine_dir);
    }

    #[tokio::test]
    async fn test_add_relationship_create_pending() {
        // clear db
        reset_db().await;
        // load in grapevine dir
        let grapevine_dir = grapevine_dir().unwrap();
        // move grapevine.key
        move_key(&grapevine_dir);

        let username = String::from("user_a");
        let username_b = String::from("user_b");

        // create accounts
        _ = create_account_cmd(&username);

        // move User A key to allow creation of User B
        rename_file(&grapevine_dir, "grapevine.key", "user_a.key");

        _ = create_account_cmd(&username_b);

        // create relationship with User A
        let output = add_relationship_cmd(&username);

        let expected_ouput = format!(
            "Relationship from {} to {} pending!\n",
            username_b, username
        );

        assert_eq!(expected_ouput, output);

        // switch back to User A
        rename_file(&grapevine_dir, "grapevine.key", "user_b.key");
        rename_file(&grapevine_dir, "user_a.key", "grapevine.key");

        // list pending relationships
        let pending_output = list_pending_relationships_cmd();
        let expected_pending_output = format!("===============================\nShowing 1 Pending relationship for {}:\n|=> \"{}\"\n\n", username, username_b);

        assert_eq!(expected_pending_output, pending_output);

        // restore to prior testing state
        restore_key(&grapevine_dir);
        remove_file(&grapevine_dir, "user_b.key");
    }

    #[tokio::test]
    async fn test_add_relationship() {
        // clear db
        reset_db().await;
        // load in grapevine dir
        let grapevine_dir = grapevine_dir().unwrap();
        // move grapevine.key
        move_key(&grapevine_dir);

        let username = String::from("user_a");
        let username_b = String::from("user_b");

        // create accounts
        _ = create_account_cmd(&username);

        // move User A key to allow creation of User B
        rename_file(&grapevine_dir, "grapevine.key", "user_a.key");

        _ = create_account_cmd(&username_b);

        // create relationship with User A
        let _ = add_relationship_cmd(&username);

        // switch back to User A
        rename_file(&grapevine_dir, "grapevine.key", "user_b.key");
        rename_file(&grapevine_dir, "user_a.key", "grapevine.key");

        // add relationship with User B and make relationships active
        let output = add_relationship_cmd(&username_b);
        let expected_output = format!(
            "Relationship from {} to {} activated!\n",
            username, username_b
        );

        assert_eq!(expected_output, output);

        // list pending relationships as User A
        let pending_output_a = list_pending_relationships_cmd();
        let expected_pending_output_a = "No Pending relationships found for this account\n\n";
        assert_eq!(pending_output_a, expected_pending_output_a);

        // list active relationships as User A
        let active_output_a = list_active_relationships_cmd();
        let expected_active_output_a = format!("===============================\nShowing 1 Active relationship for {}:\n|=> \"{}\"\n\n", username, username_b);

        assert_eq!(active_output_a, expected_active_output_a);

        // switch back to User B
        rename_file(&grapevine_dir, "grapevine.key", "user_a.key");
        rename_file(&grapevine_dir, "user_b.key", "grapevine.key");

        // list pending relationships as User B
        let pending_output_b = list_pending_relationships_cmd();
        let expected_pending_output_b = "No Pending relationships found for this account\n\n";
        assert_eq!(pending_output_b, expected_pending_output_b);

        // list active relationships as User B
        let active_output_b = list_active_relationships_cmd();
        let expected_active_output_b = format!("===============================\nShowing 1 Active relationship for {}:\n|=> \"{}\"\n\n", username_b, username);

        assert_eq!(active_output_b, expected_active_output_b);

        // restore to prior testing state
        restore_key(&grapevine_dir);
        remove_file(&grapevine_dir, "user_a.key");
    }

    #[tokio::test]
    async fn test_reject_relationship_no_pending_relationship() {
        // clear db
        reset_db().await;
        // load in grapevine dir
        let grapevine_dir = grapevine_dir().unwrap();
        // move grapevine.key
        move_key(&grapevine_dir);

        let username = String::from("user_a");
        let username_b = String::from("fake_user");

        // create accounts
        _ = create_account_cmd(&username);

        let output = reject_relationship_cmd(&username_b);
        let expected_output = format!(
            "Error: No pending relationship exists from {} to {}\n",
            username_b, username
        );

        assert_eq!(expected_output, output);

        // restore grapevine.key
        restore_key(&grapevine_dir);
    }

    #[tokio::test]
    async fn test_reject_relationship() {
        // clear db
        reset_db().await;
        // load in grapevine dir
        let grapevine_dir = grapevine_dir().unwrap();
        // move grapevine.key
        move_key(&grapevine_dir);

        let username = String::from("user_a");
        let username_b = String::from("user_b");

        // create accounts
        _ = create_account_cmd(&username);

        // move User A key to allow creation of User B
        rename_file(&grapevine_dir, "grapevine.key", "user_a.key");

        // create accounts
        _ = create_account_cmd(&username_b);

        // add relationship with User A as User B
        let _ = add_relationship_cmd(&username);

        // switch to User A
        rename_file(&grapevine_dir, "grapevine.key", "user_b.key");
        rename_file(&grapevine_dir, "user_a.key", "grapevine.key");

        // reject relationship with User B
        let output = reject_relationship_cmd(&username_b);
        let expected_output = format!(
            "Success: rejected pending relationship with \"{}\"\n",
            username_b
        );

        assert_eq!(expected_output, output);

        // list pending relationships as User A
        let pending_output = list_pending_relationships_cmd();
        let expected_pending_output = "No Pending relationships found for this account\n\n";
        assert_eq!(pending_output, expected_pending_output);

        // list active relationships as User A
        let active_output = list_active_relationships_cmd();
        let expected_active_output = "No Active relationships found for this account\n\n";

        assert_eq!(active_output, expected_active_output);

        // restore grapevine.key
        restore_key(&grapevine_dir);
        remove_file(&grapevine_dir, "user_b.key");
    }

    #[tokio::test]
    async fn test_remove_relationship_no_active_relationship() {
        // clear db
        reset_db().await;
        // load in grapevine dir
        let grapevine_dir = grapevine_dir().unwrap();
        // move grapevine.key
        move_key(&grapevine_dir);

        let username = String::from("user_a");
        let username_b = String::from("user_b");

        // create accounts
        _ = create_account_cmd(&username);

        // move User A key to allow creation of User B
        rename_file(&grapevine_dir, "grapevine.key", "user_a.key");

        // create accounts
        _ = create_account_cmd(&username_b);

        let output = remove_relationship_cmd(&username);
        let expected_output = format!(
            "Error: No relationship exists from {} to {}\n",
            username_b, username
        );

        assert_eq!(expected_output, output);

        // restore grapevine.key
        restore_key(&grapevine_dir);
        remove_file(&grapevine_dir, "user_a.key");
    }

    #[ignore]
    #[tokio::test]
    async fn test_remove_relationship() {
        // clear db
        reset_db().await;
        // load in grapevine dir
        let grapevine_dir = grapevine_dir().unwrap();
        // move grapevine.key
        move_key(&grapevine_dir);

        let username = String::from("user_a");
        let username_b = String::from("user_b");

        // create accounts
        _ = create_account_cmd(&username);

        // move User A key to allow creation of User B
        rename_file(&grapevine_dir, "grapevine.key", "user_a.key");

        // create accounts
        _ = create_account_cmd(&username_b);

        // add relationship with User A as User B
        let _ = add_relationship_cmd(&username);

        // switch to User A
        rename_file(&grapevine_dir, "grapevine.key", "user_b.key");
        rename_file(&grapevine_dir, "user_a.key", "grapevine.key");

        // add relationship with User B as User A
        let _ = add_relationship_cmd(&username_b);

        // nullify relationship with User B
        let output = reject_relationship_cmd(&username_b);
        println!("Output: {:?}", output);

        // restore grapevine.key
        restore_key(&grapevine_dir);
        remove_file(&grapevine_dir, "user_b.key");
    }

    #[ignore]
    #[tokio::test]
    async fn test_remove_relationship_already_nullified() {
        // clear db
        reset_db().await;
        // load in grapevine dir
        let grapevine_dir = grapevine_dir().unwrap();
        // move grapevine.key
        move_key(&grapevine_dir);

        let username = String::from("user_a");
        let username_b = String::from("user_b");

        // create accounts
        _ = create_account_cmd(&username);

        // move User A key to allow creation of User B
        rename_file(&grapevine_dir, "grapevine.key", "user_a.key");

        // create accounts
        _ = create_account_cmd(&username_b);

        // add relationship with User A as User B
        let _ = add_relationship_cmd(&username);

        // switch to User A
        rename_file(&grapevine_dir, "grapevine.key", "user_b.key");
        rename_file(&grapevine_dir, "user_a.key", "grapevine.key");

        // add relationship with User B as User A
        let _ = add_relationship_cmd(&username_b);

        // nullify relationship with User B
        let _ = reject_relationship_cmd(&username_b);
        // attempt to nullify relationship again
        let output = remove_relationship_cmd(&username_b);
        println!("Output: {:?}", output);

        // restore grapevine.key
        restore_key(&grapevine_dir);
        remove_file(&grapevine_dir, "user_b.key");
    }

    #[ignore]
    #[tokio::test]
    async fn test_relationship_list_commands() {
        todo!("Unimplemented");
    }
}
