#!/bin/sh

#default config
BOARD=CR9531
VERSION_NAME=soft_version
CONFIG_NAME=CR9531.config
CONFIG_PATH="./build_config"
CONFIG_SUFFIX=".config"
if [ ! -z "$1" ];then
	BOARD=$1
fi

CONFIG_NAME=${BOARD}${CONFIG_SUFFIX}

if [ ! -e "${CONFIG_PATH}/${CONFIG_NAME}" ];then
	echo "Warning:${CONFIG_PATH}/${CONFIG_NAME} isn't exist."
	exit
fi

echo "Info:will build package for $BOARD ..."

cp ${CONFIG_PATH}/${CONFIG_NAME} .config


DIST=$BOARD
sed -i "s/option hostname.*$/option hostname $DIST/" ./package/base-files/files/etc/config/system
sed -i "s/CONFIG_VERSION_DIST=\".*\"/CONFIG_VERSION_DIST=\"$DIST\"/" ./.config
sed -i "s/CONFIG_VERSION_NUMBER=\".*\"/CONFIG_VERSION_NUMBER=\"`date +%Y%m%d%H%M`\"/" ./.config
touch ./package/base-files/files/etc/openwrt_release

#make

test $? -eq 0 || exit 1

DIST=`cat .config | grep CONFIG_VERSION_DIST | awk -F\" '{print $2}'`
SOFT_VERSION=`cat ${CONFIG_PATH}/${VERSION_NAME}`
BUILD_VERSION=`cat .config | grep CONFIG_VERSION_NUMBER | awk -F\" '{print $2}'`

ls bin/ar71xx/*.bin | grep -v squashfs-sysupgrade | xargs rm >/dev/null 2>&1
mkdir -p bin/ar71xx/pkg

if [ -z ${SOFT_VERSION} ];then
	echo "Warning:${CONFIG_PATH}/${VERSION_NAME} isn't exist, using default version 1.0."
	SOFT_VERSION="V1.0"
fi
echo mv bin/ar71xx/*squashfs-sysupgrade*bin bin/ar71xx/pkg/${DIST}-${SOFT_VERSION}-${BUILD_VERSION}
mv bin/ar71xx/*squashfs-sysupgrade*bin bin/ar71xx/pkg/${DIST}-${SOFT_VERSION}-${BUILD_VERSION}

