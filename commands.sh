#!/bin/bash

PKCSLIB=/usr/local/lib/softhsm/libsofthsm2.so
openssl ecparam -name prime256v1 -outform der | xxd
softhsm2-util --init-token --slot 0 --label cop # [U: 123456 / SO: 5528999]
pkcs11-tool --provider --list-all
pkcs11-tool --module $PKCSLIB --show-info
pkcs11-tool --module $PKCSLIB --list-slots
pkcs11-tool --module $PKCSLIB --login --list-object

echo 'SUBSYSTEM=="usb", MODE="0660", GROUP="plugdev"' > /etc/udev/rules.d/00-usb-permissions.rules
udevadm control --reload-rules
