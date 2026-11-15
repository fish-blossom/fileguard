#!/usr/bin/env python3
import os, sys
for n in os.listdir(sys.argv[1]):
    if n.endswith('.JPG'):
        os.rename(os.path.join(sys.argv[1], n), os.path.join(sys.argv[1], n[:-4] + '.jpg'))
