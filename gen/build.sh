#!/bin/sh
set -e

CC=gcc
CFLAGS="-O3 -Wall -Wextra -std=c99 -pedantic $(pkg-config --cflags openssl)" 
LIBS="$(pkg-config --libs openssl)"

mkdir -p data

$CC -o words $CFLAGS words.c $LIBS
./words <words.list >data/word-hashes.list

$CC -o blobs $CFLAGS blobs.c $LIBS
./blobs data >data/blob-hashes.list