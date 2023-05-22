# DFFBOT (Directed fuzzing for binary-only targets)

This repository contains the scripts for calculating the distances for the QEMU port of [AFLGo](https://github.com/aflgo/aflgo).
It is a base for the master thesis "Implementing and evaluating a directed fuzzer for binary-only targets".

Other required repositories:
- https://github.com/DFFBOT/Docker-Scripts
- https://github.com/DFFBOT/qemuafl


## What is this repository

This repository is used to calculate the distances files for the QEMU port of AFLGo
that is used on QEMU for the directed-guided fuzzing with the help of AFL.

## Building AFLGo-QEMU (DFFBOT)

### Docker

Build and execute the Docker file `Dockerfile_DFFBOT` on https://github.com/DFFBOT/Docker-Scripts to start with fuzzing.

### Manual

To build the fuzzer for binary targets, LLVM is required.
It is currently tested with LLVM 11.0 on Debian bullseye.

```
# Install the packages
apt install -y autoconf automake libtool-bin libboost-all-dev libclang-11.0-dev

mkdir build
cd build

# Building QEMU with distance changes
git clone https://github.com/DFFBOT/qemuafl qemuafl
cd qemuafl
./configure --audio-drv-list= --disable-blobs --disable-bochs --disable-brlapi --disable-bsd-user --disable-bzip2 --disable-cap-ng --disable-cloop --disable-curl --disable-curses --disable-dmg --disable-fdt --disable-gcrypt --disable-glusterfs --disable-gnutls --disable-gtk --disable-guest-agent --disable-iconv --disable-libiscsi --disable-libnfs --disable-libssh --disable-libusb --disable-linux-aio --disable-live-block-migration --disable-lzo --disable-nettle --disable-numa --disable-opengl --disable-parallels --disable-plugins --disable-qcow1 --disable-qed --disable-rbd --disable-rdma --disable-replication --disable-sdl --disable-seccomp --disable-sheepdog --disable-smartcard --disable-snappy --disable-spice --disable-system --disable-tools --disable-tpm --disable-usb-redir --disable-vde --disable-vdi --disable-vhost-crypto --disable-vhost-kernel --disable-vhost-net --disable-vhost-scsi --disable-vhost-user --disable-vhost-vdpa --disable-vhost-vsock --disable-virglrenderer --disable-virtfs --disable-vnc --disable-vnc-jpeg --disable-vnc-png --disable-vnc-sasl --disable-vte --disable-vvfat --disable-xen --disable-xen-pci-passthrough --disable-xfsctl --target-list=x86_64-linux-user --without-default-devices --enable-pie --disable-strip --enable-debug --enable-debug-info --enable-debug-mutex --enable-debug-stack-usage --enable-debug-tcg --enable-qom-cast-debug --disable-werror
make -j$(nproc)

cd ..

# Building AFLGo
export CXX=clang++
export CC=clang
git clone https://github.com/aflgo/aflgo.git aflgo
cd aflgo
make clean all

# Copying the QEMU to AFLGo
cp ../qemuafl/build/qemu-x86_64 afl-qemu-trace
```

Then AFLGo is ready to fuzz with binary targets.
To supply the distance file, use the ENV-Variable `AFL_DISTANCE_FILE` with the corresponding path, e.g. `export AFL_DISTANCE_FILE=/tmp/dffbot_distance.txt`.


### Running

On Docker start the container by using `docker run -ti ...` and if you build AFLGo and QEMU by yourself, navigate to the path. Ensure that `$AFL_DISTANCE_FILE` is set and then you can use `afl-fuzz` with `-Q` to
directed fuzz the binary with QEMU, e.g. `./afl-fuzz -Q -m none -z exp -c 45m -i in -o "out" ./xmllint --valid --recover @@`.


## Requirements

This repository requires Python (tested on `3.11`) and the python requirements in the `requirements.txt` file.
You can use `virtualenv` with `pip install` to install the requirements:
```
virtualenv -p python3 venv
source venv/bin/activate
pip install -r requirements.txt
```

## Example commands

The commands uses the calculator in `examples/calculator` as base.
It can be build with `cmake` with included debug flag.

- `python3 -m dffbot convert-aflgo-to-dffbot ./Calculator /tmp/distance.cfg.txt /tmp/dffbot_distances.txt`
- `python3 -m dffbot convert-dffbot-to-aflgo ./Calculator /tmp/dffbot_distances.txt /tmp/distance.cfg.txt`
- `python3 -m dffbot generate-distances ./Calculator 0x400c7b 0x400c21 /tmp/dffbot_distances.txt`
- `python3 -m dffbot generate-distances-from-debug ./Calculator /tmp/BBtargets.txt /tmp/dffbot_distances.txt`


Content of BBtargets.txt:
```
calculator.c:15
calculator.c:19
```