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
# ## accept relationship request from alice to bob
# mv bob.key grapevine.key
# grapevine relationship add alice
# printf "\n"

# ## Prove degree 2 relationship to alice's phrase as bob
# grapevine proof prove-available
# mv grapevine.key bob.key

# ## Prove degree 3 relationship to alice's phrase as charlie through bob

# mv charlie.key grapevine.key
# grapevine proof prove-available
# mv grapevine.key charlie.key

# ## Prove degree 4 relationship to alice's phrase as the_user through charlie
# mv the_user.key grapevine.key
# grapevine proof prove-available
# mv grapevine.key the_user.key

## CLEANUP
# rm alice.key bob.key
if [ -f real.key ]; then
  mv real.key grapevine.key
fi