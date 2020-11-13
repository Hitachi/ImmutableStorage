#!/bin/bash
set -e
BIN_PATH=/var/lib/ImmutableST/bin

if [ "$1" == "start" ]; then
    $BIN_PATH/immsSvc preloadImg
fi

$BIN_PATH/immsSvc caSvc $@
$BIN_PATH/immsSvc httpSvc $@
$BIN_PATH/immsSvc immSvc $@
