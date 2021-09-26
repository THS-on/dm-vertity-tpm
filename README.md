# dm-verity TPM agent
This is a proof of concept of monitoring the state of a dm-verity target from userland 
and storing the changes into PCR 10 of the TPM.

# Installation
## Dependencies
* libcryptsetup-dev
* libtss2-dev
* libssl-dev
* libspdlog-dev
* cmake
* g++ or clang

## Build
 * `cmake .`
 * `make`

# Usage
Run: `dm-verity-agent /dev/mapper/DEVICE_NAME /path/to/log`.

The agent will extend the PCR with the name, root hash and if the device is valid on startup and on change.
The PCR will be extended with the hash "INVALID" when the program exits. 

# Notes
The Linux kernel with IMA now has initial support for measuring device mapper targets 
and that functionality should be used instead of using this agent.