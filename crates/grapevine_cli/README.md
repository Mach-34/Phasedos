# Grapevine CLI

```
    ______                           _
   / ____/________ _____  ___ _   __(_)___  ___
  / / __/ ___/ __ `/ __ \/ _ \ | / / / __ \/ _ \
 / /_/ / /  / /_/ / /_/ /  __/ |/ / / / / /  __/
 \____/_/   \__,_/ .___/\___/|___/_/_/ /_/\___/
                /_/

```

## CLI Installation instructions

1. clone this repo `git clone https://github.com/mach-34/grapevine && cd grapevine`
2. set the env `echo "GRAPEVINE_SERVER=https://grapevine.mach34.space" > ./crates/grapevine_cli/.env`
3. build the cli `cargo install --path ./crates/grapevine_cli`

## Usage

Note: see scripts to see how you can move the ~/.grapevine/grapevine.key file to simulate multi-user access

### Create a new account

`grapevine register-account <username>`

Creates a new account and registers it with the grapevine service. This will automatically generate a BJJ keypair. Usernames must be < 30 ASCII characters.

You must keep track of this information- in the current version of Grapevine, if you lose your private key you will be unable to access your account.

### Get your account details

`grapevine get-account`

Recall the locally stored information about your account

### Sync nonce

`grapevine sync-nonce`

This is largely a crutch for immature code. There are certain conditions where the local nonce and server nonce can desync. Run this command to resync your account if you experience a 401 failure.

### Add Relationship

`grapevine add-relationship <username>`

In grapevine, in order for someone else to build a proof from your degree proofs, they must receive an auth signature from you. Adding a relationship involves you signing their public key so that they can build proofs on top of your proofs. Note that this is not a bi-directional action, and they must call `add-relationship` with your username for you to build proofs from their proofs.

### Create new phrases

`grapevine create-phrase <phrase>`

Degree proof chains are built starting with knowledge of a phrase at the beginning. You can create the head for a degree proof chain by creating a new phrase. Phrases must be < 180 ASCII characters.

### Prove new degrees

`grapevine prove-new`

Depending on new relationships that have added you, or the new degree proofs created by your relationships over time, you will gain access to new degree proof chains or lower degree connections within chains you're already a part of. You can automatically update your connections with this command.

### Get all of your degree connections

`grapevine get-degrees`

You can get all of your degrees of connections on proof chains with this command. Note that you will only store your lowest degree proof from a chain, and when you obtain a lower degree proof in a chain you were already a part of, it will be deleted and not shown here.
