#!/bin/bash
set -e
BIN_PATH=/var/lib/ImmutableST/bin

$BIN_PATH/immsSvc preloadImg

$BIN_PATH/immsSvc caSvc $@
$BIN_PATH/immsSvc httpSvc $@
$BIN_PATH/immsSvc immSvc $@
