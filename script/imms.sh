#!/bin/bash
set -e
BIN_PATH=/var/lib/ImmutableST/bin

if [ "$1" == "start" ]; then
    if [ -x $BIN_PATH/remount_cgroup.sh ]; then
        . $BIN_PATH/remount_cgroup.sh
    fi
    $BIN_PATH/immsSvc preloadImg
fi

$BIN_PATH/immsSvc caSvc $@
$BIN_PATH/immsSvc httpSvc $@
$BIN_PATH/immsSvc immSvc $@

if [ "$1" == "start" ]; then
    $BIN_PATH/immsSvc caSvc getPass
fi
