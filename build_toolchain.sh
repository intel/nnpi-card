#!/bin/sh
#
# PREREQUISITES:
#
# Centos: sudo yum install -y bc perl-devel git perl-Thread-Queue perl-Data-Dumper texinfo-5.1-5.el7.x86_64
#
# Ubuntu: sudo apt-get install sed make binutils gcc g++ bash patch gzip bzip2 perl tar cpio python unzip rsync wget libncurses-dev libelf-dev libssl-dev bison libarchive-dev
#
# Usage:
# build_toolchain.sh <output_dir>
#
# Default output_dir=nnpi_os_buildroot/build
#
# toolchain will be located in $output_dir/toolchain

REPO_DIR=$(dirname $0)
TOOLCHAIN_DIR=toolchain
TOOLCHAIN_BUILD_DIR=build

error_check () {
	ret=$?
	if [ $ret != 0 ]; then
		echo $1 failed, return value $ret
		exit $ret
	fi
}

if [ -z "$1" ]; then
	OUTPUT_DIR=nnpi_os_buildroot/$TOOLCHAIN_BUILD_DIR
else
	OUTPUT_DIR=$1
fi

mkdir -p $OUTPUT_DIR
error_check "mkdir $OUTPUT_DIR"

rm -rf $OUTPUT_DIR/$TOOLCHAIN_DIR
error_check "rm -rf $OUTPUT_DIR/$TOOLCHAIN_DIR"

echo "toolchain output directory: $OUTPUT_DIR/$TOOLCHAIN_DIR"

cd nnpi_os_buildroot
#to enable toolchain build
echo "BR2_COMPILER_PARANOID_UNSAFE_PATH=n" >> configs/SPH_x86_64_efi_nnpi_defconfig
make SPH_x86_64_efi_nnpi_defconfig  O=$TOOLCHAIN_BUILD_DIR
error_check "make SPH_x86_64_efi_Simics_nnpi_defconfig"

set -x; 
cd $TOOLCHAIN_BUILD_DIR
make sdk
error_check "make sdk"

cd ../../
mv nnpi_os_buildroot/$TOOLCHAIN_BUILD_DIR/host $OUTPUT_DIR/$TOOLCHAIN_DIR
error_check "mv toolchain"

echo "Toolchain is ready at $OUTPUT_DIR/$TOOLCHAIN_DIR"
