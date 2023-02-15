#!/bin/bash
# Script outline to install and build kernel.
# Author: Siddhant Jajoo.

set -e
set -u

OUTDIR=/tmp/aeld
KERNEL_REPO=git://git.kernel.org/pub/scm/linux/kernel/git/stable/linux-stable.git
KERNEL_VERSION=v5.1.10
BUSYBOX_VERSION=1_33_1
FINDER_APP_DIR=$(realpath $(dirname $0))
ARCH=arm64
CROSS_COMPILE=aarch64-none-linux-gnu-
export SYSROOT=$(${CROSS_COMPILE}gcc -print-sysroot)


if [ $# -lt 1 ]
then
	echo "Using default directory ${OUTDIR} for output"
else
	OUTDIR=$1
	echo "Using passed directory ${OUTDIR} for output"
fi

mkdir -p ${OUTDIR}

cd "$OUTDIR"
if [ ! -d "${OUTDIR}/linux-stable" ]; then
    #Clone only if the repository does not exist.
	echo "CLONING GIT LINUX STABLE VERSION ${KERNEL_VERSION} IN ${OUTDIR}"
	git clone ${KERNEL_REPO} --depth 1 --single-branch --branch ${KERNEL_VERSION}
fi
if [ ! -e ${OUTDIR}/linux-stable/arch/${ARCH}/boot/Image ]; then
    cd linux-stable
    echo "Checking out version ${KERNEL_VERSION}"
    git checkout ${KERNEL_VERSION}

    # TODO: Add your kernel build st

 
    echo "here we go"
    #deep cleaning kernel build tree thanks to mproper
    make ARCH=arm64 CROSS_COMPILE=aarch64-none-linux-gnu- mrproper  
    #building deconfig file and set up for our virt arm device for qemu
    echo "echo 2"
    make ARCH=arm64 CROSS_COMPILE=aarch64-none-linux-gnu- defconfig
    echo "my prob"
    #build vimlinux target, builds kernel image with QEMU
    echo "3"
    make -j4 ARCH=arm64 CROSS_COMPILE=aarch64-none-linux-gnu- all
    #Build kernel modules and device tree
    make ARCH=arm64 CROSS_COMPILE=aarch64-none-linux-gnu- modules
    echo "4"
    make ARCH=arm64 CROSS_COMPILE=aarch64-none-linux-gnu- dtbs
    echo "and just like that its built"


fi

echo "Adding the Image in outdir"
cp ${OUTDIR}/linux-stable/arch/${ARCH}/boot/Image ${OUTDIR}

echo "Creating the staging directory for the root filesystem"
cd "$OUTDIR"
if [ -d "${OUTDIR}/rootfs" ]
then
	echo "Deleting rootfs directory at ${OUTDIR}/rootfs and starting over"
    sudo rm  -rf ${OUTDIR}/rootfs
fi

# TODO: Create necessary base directories
mkdir -p ${OUTDIR}/rootfs && cd ${OUTDIR}/rootfs
mkdir -p bin dev etc home lib lib64 proc sbin sys tmp usr var
mkdir -p usr/bin usr/lib usr/sbin
mkdir -p var/log


cd "$OUTDIR"
if [ ! -d "${OUTDIR}/busybox" ]
then
git clone git://busybox.net/busybox.git
    cd busybox
    git checkout ${BUSYBOX_VERSION}
    # TODO:  Configure busybox
    make distclean
    make defconfig
    echo "config is good"

else
    cd busybox
    
fi

echo "i have hope"
# TODO: Make and install busybox
echo "ok now"
make ARCH=${ARCH} CROSS_COMPILE=${CROSS_COMPILE}
make CONFIG_PREFIX=${OUTDIR}/rootfs ARCH=${ARCH} CROSS_COMPILE=${CROSS_COMPILE} install

echo "Library dependencies"
cd ${OUTDIR}/rootfs
${CROSS_COMPILE}readelf -a bin/busybox | grep "program interpreter"
${CROSS_COMPILE}readelf -a bin/busybox | grep "Shared library"

# TODO: Add library dependencies to rootfs
# doing the sysroot so I can see the needed libraries
echo "did i make it this far?"

cd ${OUTDIR}/rootfs
cp -a ${SYSROOT}/lib/ld-linux-aarch64.so.1 lib
cp -a ${SYSROOT}/lib64/ld-2.31.so lib64
cp -a ${SYSROOT}/lib64/libm.so.6 lib64
cp -a ${SYSROOT}/lib64/libresolv.so.2 lib64
cp -a ${SYSROOT}/lib64/libc.so.6 lib64
cp -a ${SYSROOT}/lib64/libm-2.31.so lib64
cp -a ${SYSROOT}/lib64/libresolv-2.31.so lib64
cp -a ${SYSROOT}/lib64/libc-2.31.so lib64


# TODO: Make device nodes
echo "here i go making device nodes"
cd ${OUTDIR}/rootfs
sudo mknod -m 666 dev/null c 1 3
sudo mknod -m 600 dev/console c 5 1


# TODO: Clean and build the writer utility
cd ${FINDER_APP_DIR}
make clean
make ARCH=arm64 CROSS_COMPILE=${CROSS_COMPILE}
echo "phew just cleaned house"


# TODO: Copy the finder related scripts and executables to the /home directory
# on the target rootfs
echo "bout to copy some stuff in finder app"
cp writer.c writer.sh finder.sh writer autorun-qemu.sh ${OUTDIR}/rootfs/home
cp finder-test.sh ${OUTDIR}/rootfs/home
cp -r ./conf/ ${OUTDIR}/rootfs/home/


# TODO: Chown the root directory
echo "changing ownership gang"
cd ${OUTDIR}/rootfs/
sudo chown -R root:root *

# TODO: Create initramfs.cpio.gz

echo "last steps fingers crossed!"


find . | cpio -H newc -ov --owner root:root > ${OUTDIR}/initramfs.cpio
cd ..
gzip -f initramfs.cpio
