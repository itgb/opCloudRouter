#!/usr/bin/env bash
cp -f 9563_clr.conf .config
./gen_version.sh set ar71xx generic
make V=s
./version_file.sh set ar71xx ap152


