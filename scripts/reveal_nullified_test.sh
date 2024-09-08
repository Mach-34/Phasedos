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
rm user_a.key user_b.key user_c.key

## create first test user
grapevine account register user_a
mv grapevine.key user_a.key

## create second test user
grapevine account register user_b
mv grapevine.key user_b.key

## create third test user
grapevine account register user_c
mv grapevine.key user_c.key

## create a relationship with User B as User A
mv user_a.key grapevine.key
grapevine relationship add user_b

## create a relationship with User C as User A
grapevine relationship add user_c

## list relationships requiring nullification as User A
grapevine relationship reveal-nullified

## switch to User B
mv grapevine.key user_a.key
mv user_b.key grapevine.key
echo "Switched from User A to User B!"

## add relationship with User A as User B
grapevine relationship add user_a

## switch to User C
mv grapevine.key user_b.key
mv user_c.key grapevine.key
echo "Switched from User B to User C!"

## add relationship with User A as User C
grapevine relationship add user_a

## switch to User A
mv grapevine.key user_c.key
mv user_a.key grapevine.key
echo "Switched from User C to User A!"

## list active relationships for User A
grapevine relationship list

## switch to User B
mv grapevine.key user_a.key
mv user_b.key grapevine.key
echo "Switched from User A to User B!"

## nullify relationship with User A as User B
grapevine relationship remove user_a

## switch to User A
mv grapevine.key user_b.key
mv user_a.key grapevine.key
echo "Switched from User B to User A!"

## list relationships to nullify as User A
grapevine relationship reveal-nullified

## switch to User C
mv grapevine.key user_a.key
mv user_c.key grapevine.key
echo "Switched from User A to User C!"
 
## nullify relationship with User A as User C
grapevine relationship remove user_a

## switch to User A
mv grapevine.key user_c.key
mv user_a.key grapevine.key
echo "Switched from User C to User A!"

## list relationships to nullify as User A
grapevine relationship reveal-nullified

## nullify relationship with User B as User A
grapevine relationship remove user_b

## list relationships to nullify as User A
grapevine relationship reveal-nullified

## nullify relationship with User C as User A
grapevine relationship remove user_c

## list relationships to nullify as User A
grapevine relationship reveal-nullified

## CLEANUP
mv ~/.grapevine/grapevine.key ~/.grapevine/user_a.key
rm ~/.grapevine/user_a.key ~/.grapevine/user_b.key ~/.grapevine/user_c.key
if [ -f real.key ]; then
  mv real.key grapevine.key
fi