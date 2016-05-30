#!/usr/bin/env bash

#executes this file before "make V=s"

VERSION_TMP_FILE="bin/openwrt_custom.version"
CFG_VERSION_VAR_NAME="CONFIG_VERSION_NUMBER"
CFG_VERSION_FILE=".config"
OLD_CFG_VERSION_FILE=".config.old"
	
usage() {
	cat <<EOF
Usage: $0 [options] <command> [arguments]
Commands:
	help              			This help text
	set <target> <subtarget>    set target name and subtarget
	
Options:

EOF
	exit ${1:-1}
}

version_replace() {
	local version_file="$1"
	local target="$2"
	local subtarget="$3"
	local time_stamp="$4"
	echo "target:$target, subtarget:$subtarget, version_file:$version_file, time_stamp:$time_stamp"

	cfg_version_num=`cat $version_file | grep $CFG_VERSION_VAR_NAME`
	echo "[cur_version]:"$cfg_version_num
	n_cfg_version_num="${CFG_VERSION_VAR_NAME}=\"${time_stamp}\""
	echo "[new_version]:"$n_cfg_version_num

	cfg_version_num=${cfg_version_num//\"/\\\"}
	n_cfg_version_num=${n_cfg_version_num//\"/\\\"}
	#echo "s/$cfg_version_num/$n_cfg_version_num/g"
	sed -i 's/'$cfg_version_num'/'$n_cfg_version_num'/g' $version_file
	echo "changing $cfg_version_num to $n_cfg_version_num in $version_file"
}


version_set() {
	local target="$1"
	local subtarget="$2"
	local time_stamp="`date +%y%m%d%H%M%S`"
	echo "target:$target, subtarget:$subtarget, time_stamp:$time_stamp "
	
	echo $time_stamp > $VERSION_TMP_FILE
	echo "will del old openwrt_version & openwrt_release"
	version_replace $CFG_VERSION_FILE $target $subtarget $time_stamp
	version_replace $OLD_CFG_VERSION_FILE $target $subtarget $time_stamp

	touch ./package/base-files/files/etc/openwrt_release 
}

COMMAND="$1"; shift
case "$COMMAND" in
	help) usage 0;;
	set) version_set "$@";;
	*) usage;;
esac






