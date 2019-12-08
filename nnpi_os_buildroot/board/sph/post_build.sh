#!/bin/bash

set -x

#BUILD_FLAVOUR comes from POST_ARGS defined in config file
BUILD_FLAVOUR=$4
BUILD_FLAVOUR_LC=${BUILD_FLAVOUR,,}
ROOTFS_PATH=$1
echo "Buildroot Build Flavour is: "${BUILD_FLAVOUR}
PLATFORM_KERNEL_AUTO=${PWD}/../../automation/
BOARD_SPH_PATH=${PWD}/board/sph/
BUILD_CONFIGURATION=""

function add_line_to_file() {
	line=$1
	file=$2
	if [ -f "${file}" ]; then
		n=`grep -x -F "${line}" "${file}" | wc -l`
		if [ "${n}" -eq "0" ]; then
			echo "Adding ${line} into ${file}"
			echo "${line}">>"${file}"
		fi
	else
		echo "add_line_to_file ${line} ${file} failed (file not found)"	
		read -p "Press Enter..."
	fi
}

RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m' # No Color

function check_success() {
	retcode=$1
	action=$2
	filename=$3
	if [ ${retcode} -eq 0 ]; then
    		echo -e "${GREEN} ${action} on ${filename} OK ${NC}"
	else
		echo -e "${RED}"
		echo -e "************FAIL FAIL FAIL**************"
    		echo -e "${action} on ${filename} FAILED"
		echo -e "************FAIL FAIL FAIL**************"
		echo -e "${NC}"
		exit -1
	fi	
}



if [ -f ${BOARD_SPH_PATH}/packing_list ]; then
	. ${BOARD_SPH_PATH}/packing_list
	if [ -z $BUILD_CONFIGURATION ]; then
		echo "post_build.sh ERROR: invalid/empty packing_list file - exiting..."
		exit 1
	fi
	#KVER=5.1 (KVER and KVER_REAL are now calculated in common_defs.sh)
	pushd ${PLATFORM_KERNEL_AUTO}
		. common_defs.sh -f ${BUILD_FLAVOUR_LC} -c ${BUILD_CONFIGURATION}
	popd

	if [ -z $KVER_REAL ]; then
		echo "post_build.sh ERROR: Undefined KVER_REAL - exiting..."
		exit 1
	fi
	for ko_mod in "${KO_MODS_ARR[@]}"
	do
       		add_line_to_file "${ko_mod}" "${ROOTFS_PATH}/lib/modules/${KVER_REAL}/modules.dep"
	done
	fi

#GETTY
add_line_to_file "### SPH ### put a getty on tty1 (VGA)" "${ROOTFS_PATH}/etc/inittab"
add_line_to_file "tty1::respawn:/sbin/getty -L  tty1 0 vt100 # VGA" "${ROOTFS_PATH}/etc/inittab" 

#SSHD_CONFIG
add_line_to_file "### SPH ### Enable ssh login from "root" user" "${ROOTFS_PATH}/etc/ssh/sshd_config"
add_line_to_file "PermitRootLogin yes" "${ROOTFS_PATH}/etc/ssh/sshd_config"

#Add mount of /sys/kernel/debug debugfs filesystem only for Debug flabour
if [ "${BUILD_FLAVOUR}" == "Debug" ]; then
	add_line_to_file "debugfs /sys/kernel/debug debugfs defaults" "${ROOTFS_PATH}/etc/fstab"
fi


if [ "${BUILD_CONFIGURATION}" == "sph_sa" ]; then
	sed -i 's/sph_start_placeholder/start_sph_sa/' ${ROOTFS_PATH}/usr/local/bin/sph_platform_start 
else
	sed -i 's/sph_start_placeholder/start_sph_ep/' ${ROOTFS_PATH}/usr/local/bin/sph_platform_start 
fi
