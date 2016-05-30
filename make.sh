#!/bin/sh

#cp build_config/build.config .config

DIST=CROUTER
sed -i "s/option hostname.*$/option hostname $DIST/" ./package/base-files/files/etc/config/system
sed -i "s/CONFIG_VERSION_DIST=\".*\"/CONFIG_VERSION_DIST=\"$DIST\"/" ./.config
sed -i "s/CONFIG_VERSION_NUMBER=\".*\"/CONFIG_VERSION_NUMBER=\"`date +%Y%m%d%H%M`\"/" ./.config
touch ./package/base-files/files/etc/openwrt_release

make

test $? -eq 0 || exit 1

DIST=`cat .config | grep CONFIG_VERSION_DIST | awk -F\" '{print $2}'`
VERSION=`cat .config | grep CONFIG_VERSION_NUMBER | awk -F\" '{print $2}'`

ls bin/ar71xx/*.bin | grep -v squashfs-sysupgrade | xargs rm >/dev/null 2>&1
mkdir -p bin/ar71xx/pkg
echo mv bin/ar71xx/*squashfs-sysupgrade*bin bin/ar71xx/pkg/${DIST}-v4.0-${VERSION}
mv bin/ar71xx/*squashfs-sysupgrade*bin bin/ar71xx/pkg/${DIST}-v4.0-${VERSION}

