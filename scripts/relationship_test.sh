#!/bin/bash

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

## clean up previous keyfiles if they exist
rm user_a.key user_b.key

# CHECK RELATIONSHIP ADDING/ REJECTION
## create first test user
grapevine account register user_a
mv grapevine.key user_a.key

## create second test user
grapevine account register user_b
mv grapevine.key user_b.key

## create a relationship with User B as User A
mv user_a.key grapevine.key
grapevine relationship add user_b

## switch to User B
mv grapevine.key user_a.key
mv user_b.key grapevine.key
echo "Switched from User A to User B!"

## log pending relationships for User B
grapevine relationship pending

## reject pending relationship first time
grapevine relationship reject user_a

## add relationship with User A as User B
grapevine relationship add user_a

## switch back to User A
mv grapevine.key user_b.key
mv user_a.key grapevine.key
echo "Switched from User B to User A!"

## list pending relationships
grapevine relationship pending

## accept relationship request from User B
grapevine relationship add user_b

## list active relationships for User A
grapevine relationship list

## switch to User B and list active relationships
mv grapevine.key user_a.key
mv user_b.key grapevine.key
echo "Switched from User A to User B!"
grapevine relationship list
mv grapevine.key user_b.key
# CHECK RELATIONSHIP NULLIFICATIION

## create proofs with User A and B
mv user_a.key grapevine.key
grapevine proof sync
mv grapevine.key user_a.key
mv user_b.key grapevine.key
grapevine proof sync
mv grapevine.key user_b.key

# ## create user c with relationship with Bob
grapevine account register user_c
grapevine relationship add user_b
mv grapevine.key user_c.key
mv user_b.key grapevine.key
grapevine relationship add user_c
mv grapevine.key user_b.key

## Check that user c has available proof to build with alice as degree 1
mv user_c.key grapevine.key
grapevine proof available
mv grapevine.key user_c.key

## User a nullifies relationship from user b
mv user_a.key grapevine.key
grapevine relationship remove user_b
mv grapevine.key user_a.key

## Check that user c does not have available proof to build with alice as degree 1
mv user_c.key grapevine.key
grapevine proof available
mv grapevine.key user_c.key

## CLEANUP
rm ~/.grapevine/user_a.key ~/.grapevine/user_b.key ~/.grapevine/user_c.key
if [ -f real.key ]; then
  mv real.key grapevine.key
fi