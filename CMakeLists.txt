cmake_minimum_required(VERSION 3.20)

project(dm-verity-agent VERSION 0.1)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# Specify dm-verity device and log path for systemd service
set(DM_VERITY_DEVICE "/dev/mapper/rootfs")
set(LOG_PATH "/var/log/dm-verity.log")


subdirs(src service)