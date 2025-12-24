#!/usr/bin/env python3

import os
import shutil
import time

SOURCE_DIR = "src/test"
DEST_DIR = "/home/coder/Workspace/test_saved"

while True:
    if os.path.isdir(SOURCE_DIR):
        if os.path.exists(DEST_DIR):
            shutil.rmtree(DEST_DIR)
        shutil.copytree(SOURCE_DIR, DEST_DIR)
        print("Folder Captured!")
    time.sleep(0.5)
