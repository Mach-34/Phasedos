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

## Create Users and add the_user
grapevine account register the_user
mv grapevine.key the_user.key
grapevine account register alice
grapevine relationship add the_user
mv grapevine.key alice.key
grapevine account register bob
grapevine relationship add the_user
mv grapevine.key bob.key
grapevine account register charlie
grapevine relationship add the_user
mv grapevine.key charlie.key
mv the_user.key grapevine.key
grapevine relationship add alice
grapevine relationship add bob
grapevine relationship add charlie
mv grapevine.key the_user.key

## Nullify relationships with the_user
mv alice.key grapevine.key
grapevine relationship remove the_user
mv grapevine.key alice.key
mv bob.key grapevine.key
grapevine relationship remove the_user
mv grapevine.key bob.key
mv charlie.key grapevine.key
grapevine relationship remove the_user
mv grapevine.key charlie.key

## List relationships

## Cleanup
rm ~/.grapevine/alice.key ~/.grapevine/bob.key ~/.grapevine/charlie.key ~/.grapevine/the_user.key 
if [ -f real.key ]; then
  mv real.key grapevine.key
fi
