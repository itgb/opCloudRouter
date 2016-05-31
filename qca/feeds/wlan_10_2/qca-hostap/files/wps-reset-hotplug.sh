#
# Copyright (c) 2013 Qualcomm Atheros, Inc..
#
# All Rights Reserved.
# Qualcomm Atheros Confidential and Proprietary.
#

if [ "$ACTION" = "released" -a "$BUTTON" = "reset" ]; then
	date > /tmp/reset_button
	echo ">>>> reset button down ${SEEN}S .... " >> /tmp/reset_button
	if [ "$SEEN" -gt 4 ]; then
		wifi down
		echo "" > /dev/console
		echo "RESET TO FACTORY SETTING EVENT DETECTED" > /dev/console
		echo "PLEASE WAIT WHILE REBOOTING THE DEVICE..." > /dev/console
		echo "timer" >  /sys/devices/platform/leds-gpio/leds/led_status_error/trigger
		echo 200 >  /sys/devices/platform/leds-gpio/leds/led_status_error/delay_on
		echo 150 >  /sys/devices/platform/leds-gpio/leds/led_status_error/delay_off
		echo "timer" >  /sys/devices/platform/leds-gpio/leds/led_status_ok/trigger
		echo 200 >  /sys/devices/platform/leds-gpio/leds/led_status_ok/delay_on
		echo 200 >  /sys/devices/platform/leds-gpio/leds/led_status_ok/delay_off		
		mtd -r erase rootfs_data
	fi
fi
