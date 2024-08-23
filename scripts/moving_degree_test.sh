#!/bin/bash

## NOTE: this test is pretty disgusting but c'est la vie for today

## if ~/.grapevine does not exist, make the folder
if [ ! -f ~/.grapevine ]; then
  mkdir ~/.grapevine
fi

## move to ~/.grapevine
cd ~/.grapevine

## if grapevine.key exists, move it to real.key
if [ -f grapevine.key ]; then
  mv grapevine.key real.key
fi

## Check if artifacts match
WASM_SHASUM="802c3bab4e326d1f2f9fd4285ea8cd67d3ba0a335a9a9ac3369402d693bf9635"
R1CS_SHASUM="faf8ad304e7edff59d1fd2f200501efbdfbf198f394c339636730c30e02f01ac"
PARAMS_SHASUM="797b5ebb6d2165cbe0d1923c9452a5442f93e91e33b84937a8753d69b9c99d9f"
check_shasum() {
    local expected_shasum="$1"
    local filepath="$2"

    # Check if the file exists
    if [ -f "$filepath" ]; then
        # Calculate the sha256sum of the file
        local file_shasum=$(sha256sum "$filepath" | awk '{ print $1 }')

        # Check if the calculated shasum matches the expected one
        if [ "$file_shasum" != "$expected_shasum" ]; then
            # If it does not match, delete the file
            rm "$filepath"
        fi
    fi
}

check_shasum "$WASM_SHASUM" "grapevine.wasm"
check_shasum "$R1CS_SHASUM" "grapevine.r1cs"
check_shasum "$PARAMS_SHASUM" "public_params.json"

### 1.
### alice <---- bob <---- charlie <---- the_user
### 
### 2.
### alice <---- bob <---- the_user 
###
### 3. 
### alice <---- the_user

# make user account (POV for the test)
grapevine account register the_user
printf "\n"
echo $(pwd)
echo $(ls)
mv grapevine.key the_user.key

## make charlie account
grapevine account register charlie
## send relationship request from charlie to the_user
grapevine relationship add the_user
printf "\n"
mv grapevine.key charlie.key
## accept relationship request from charlie to the_user
mv the_user.key grapevine.key
grapevine relationship add charlie
printf "\n"
mv grapevine.key the_user.key


## make bob account
grapevine account register bob
## send relationship request from bob to charlie
grapevine relationship add charlie
printf "\n"
mv grapevine.key bob.key
## accept relationship request from bob to charlie
mv charlie.key grapevine.key
grapevine relationship add bob
printf "\n"
mv grapevine.key charlie.key

## make alice account
grapevine account register alice
## send relationship request from alice to bob
grapevine relationship add bob
printf "\n"
## create degree 1 proof (phrase proof)
printf "\n"
mv grapevine.key alice.key
## accept relationship request from alice to bob
mv bob.key grapevine.key
grapevine relationship add alice
printf "\n"

## Prove degree 2 relationship to alice's phrase as bob
grapevine proof sync
mv grapevine.key bob.key

## Prove degree 3 relationship to alice's phrase as charlie through bob

mv charlie.key grapevine.key
grapevine proof sync
mv grapevine.key charlie.key

## Prove degree 4 relationship to alice's phrase as the_user through charlie
mv the_user.key grapevine.key
grapevine proof sync
mv grapevine.key the_user.key

## Make connection from the_user to bob
mv bob.key grapevine.key
grapevine relationship add the_user
mv grapevine.key bob.key
mv the_user.key grapevine.key
grapevine relationship add bob
grapevine proof sync
mv grapevine.key the_user.key

## Make connection from the_user to alice
mv alice.key grapevine.key
grapevine relationship add the_user
mv grapevine.key alice.key
mv the_user.key grapevine.key
grapevine relationship add alice
grapevine proof sync
mv grapevine.key the_user.key

## CLEANUP
# rm alice.key bob.key
if [ -f real.key ]; then
  mv real.key grapevine.key
fi