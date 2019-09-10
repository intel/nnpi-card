#!/bin/bash

set -x

BUILD_FLAVOUR=$4
BUILD_FLAVOUR_LC=${BUILD_FLAVOUR,,}
echo "Buildroot Build Flavour is: "${BUILD_FLAVOUR}
#sph_sa or sph_ep
BUILD_CONFIGURATION=$5 
FULL_STACK_VER_TAG=$6
PLATFORM_KERNEL_AUTO=${PWD}/../../automation/
pushd ${PLATFORM_KERNEL_AUTO}
. common_defs.sh -f ${BUILD_FLAVOUR_LC} -c ${BUILD_CONFIGURATION}
popd

#KVER=5.1 (KVER and KVER_REAL are now calculated in common_defs.sh)
#KVER_REAL=5.1.0
ROOTFS_PATH=$1

KERNEL_SRC_DIR="$BUILD_DIR/linux-$KVER"
KERNEL_HEADERS_DIR="$BUILD_DIR/linux-headers-$KVER"
TOOLCHAIN_DIR="$HOST_DIR"
echo "PWD="$PWD

THIS_MANIFEST_BASE_PATH=${PWD}/../../../

if [ "${BUILD_CONFIGURATION}" == "sph_sa" ]
then
	EXTRA_DIR=${PLATFORM_KERNEL_AUTO}extra
fi

curr_maj_ver=`grep BR2_TARGET_GENERIC_ISSUE $DEFCONFIG | sed "s/\(BR2_TARGET_GENERIC_ISSUE=\"Welcome\ to\ NNPI\ OS\ -\ V\)\([0-9A-Za-z_-]*\).\([0-9A-Za-z_-]*\).*/\2/"`
curr_min_ver=`grep BR2_TARGET_GENERIC_ISSUE $DEFCONFIG | sed "s/\(BR2_TARGET_GENERIC_ISSUE=\"Welcome\ to\ NNPI\ OS\ -\ V\)\([0-9A-Za-z_-]*\).\([0-9A-Za-z_-]*\).*/\3/"`
curr_ver=`grep BR2_TARGET_GENERIC_ISSUE $DEFCONFIG | sed "s/\(BR2_TARGET_GENERIC_ISSUE=\"Welcome\ to\ NNPI\ OS\ -\ V\)\([0-9A-Za-z_-]*\).\([0-9A-Za-z_-]*\).\([0-9A-Za-z_-]*\).*/\4/"`

VANILLA_VER_TAG="V$curr_maj_ver.$curr_min_ver.$curr_ver"
ARTIFACTS_BASE_PATH=${THIS_MANIFEST_BASE_PATH}/release_artifacts
REL_ART_PLAT_SW_BASE_PATH=${ARTIFACTS_BASE_PATH}/platform_sw/build_artifact/${BUILD_CONFIGURATION}/${BUILD_FLAVOUR}
REL_ART_INFERENCE_API_BASE_PATH=${ARTIFACTS_BASE_PATH}/inference_api/build_artifact/${BUILD_CONFIGURATION}/${BUILD_FLAVOUR^}

#Platform SW
CARD_DRIVER_ARTIFACT=*${BUILD_CONFIGURATION}-card_driver.tar.gz
CARD_TEST_ARTIFACT=*${BUILD_CONFIGURATION}-card_tests.tar.gz
CARD_SDK_ARTIFACT=*${BUILD_CONFIGURATION}-card_sdk.tar.gz
HOST_DRIVER_ARTIFACT=*${BUILD_CONFIGURATION}-host_driver.tar.gz
HOST_TEST_ARTIFACT=*${BUILD_CONFIGURATION}-host_tests.tar.gz
HOST_SDK_ARTIFACT=*${BUILD_CONFIGURATION}-host_sdk.tar.gz

#inferene API
INFERENCE_API_ARTIFACT_PATH=${ARTIFACTS_BASE_PATH}/inference_api/build_artifact/${BUILD_CONFIGURATION}/${BUILD_FLAVOUR}
INFERENCE_API_DRIVER=*-${BUILD_CONFIGURATION}-host_driver_inf_api.tar.gz
INFERENCE_API_TESTS=*-${BUILD_CONFIGURATION}-host_tests_inf_api.tar.gz
INFERENCE_API_LIGHT_TESTS=tests_inputs_light.tar.gz
INFERENCE_API_HOST_INCLUDE=*-host_include_inf_api.tar.gz

#Firmware
FIRMWARE_ARTIFACT=${ARTIFACTS_BASE_PATH}/fw_pkgs/build_artifact/ice_driver_fw_pkg_rtl_${BUILD_FLAVOUR_LC}*.tar.gz
RUNTIME_ASIP_FW=${THIS_MANIFEST_BASE_PATH}/runtime_asip_fw
RUNTIME_IVP_FW=${THIS_MANIFEST_BASE_PATH}/runtime_ivp_fw

#ice driver
ICE_DRIVER_KERNEL_ARTIFACT_TAR_PATH=${ARTIFACTS_BASE_PATH}/driver_kernel/build_artifact/${BUILD_CONFIGURATION}/${BUILD_FLAVOUR}/ice_kmd-*-${BUILD_CONFIGURATION}-${BUILD_FLAVOUR_LC}_64_driver.tar.gz
ICE_DRIVER_USER_ARTIFACT=${ARTIFACTS_BASE_PATH}/driver_user/build_artifact/${BUILD_CONFIGURATION}/${BUILD_FLAVOUR}/ice_umd-*-${BUILD_CONFIGURATION}-${BUILD_FLAVOUR_LC}_64_driver.tar.gz

ICE_DRIVER_USER_TESTS_ARTIFACT=${ARTIFACTS_BASE_PATH}/driver_user/build_artifact/${BUILD_CONFIGURATION}/${BUILD_FLAVOUR}/ice_umd-*-${BUILD_CONFIGURATION}-${BUILD_FLAVOUR_LC}_64_tests.tar.gz
ICE_DRIVER_USER_LIBS_ARTIFACT=${ARTIFACTS_BASE_PATH}/driver_user/build_artifact/${BUILD_CONFIGURATION}/${BUILD_FLAVOUR}/libs

#runtime
RUNTIME_ARTIFACT=${ARTIFACTS_BASE_PATH}/runtime/build_artifact/${BUILD_CONFIGURATION}/${BUILD_FLAVOUR}/sph_runtime_*_${BUILD_CONFIGURATION}_${BUILD_FLAVOUR}.tar.gz
RUNTIME_TEST=${ARTIFACTS_BASE_PATH}/runtime/build_artifact/${BUILD_CONFIGURATION}/${BUILD_FLAVOUR}/runtime_test_*_${BUILD_CONFIGURATION}_${BUILD_FLAVOUR}.tar.gz
VIRUS_RUNTIME_TEST=${ARTIFACTS_BASE_PATH}/runtime/build_artifact/${BUILD_CONFIGURATION}/${BUILD_FLAVOUR}/tests_inputs_virus.tar.gz

# Tools
PTU_TOOL_ARTIFACT=${ARTIFACTS_BASE_PATH}/ptu/PTU_*.tar.gz

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

## Add more meaningful version to /etc/issue - e.x.[Platform_SPH_OS_sph_ep_debug_19WW22.3.3_93_2019_05_28]
#DATE=`date +%Y%m%d`
#touch ${ROOTFS_PATH}/etc/packagename
#add_line_to_file "Platform_SPH_OS${BUILD_CONFIGURATION}_${BUILD_FLAVOUR}_${VANILLA_VER_TAG}_${DATE}" "${ROOTFS_PATH}/etc/packagename"

#If its a vanilla os then we do not pack any ingredients on ROOTFS
if [ "${BUILD_CONFIGURATION}" == "" ]
then
	echo "$0: Exiting as it's a Vanilla OS"
	exit 0
fi
VERSION_PATH=${ROOTFS_PATH}/etc/version
touch ${VERSION_PATH}

# prepare ingredients on rootfs image

if [ ! -d ${ROOTFS_PATH}/lib/modules/${KVER_REAL}/extra ]; then
	echo "Creating directory for our kernel modules"
	mkdir -p ${ROOTFS_PATH}/lib/modules/${KVER_REAL}/extra
fi

if [ ! -d "${ROOTFS_PATH}/usr/sbin/" ]; then
	mkdir -p "${ROOTFS_PATH}/usr/sbin/" 
fi

mkdir -p ${ROOTFS_PATH}/sph_tmp/driver
mkdir -p ${ROOTFS_PATH}/sph_tmp/inference_api
mkdir -p ${ROOTFS_PATH}/sph_tmp/runtime
mkdir -p ${ROOTFS_PATH}/sph_tmp/platform
mkdir -p ${ROOTFS_PATH}/usr/local/bin
mkdir -p ${ROOTFS_PATH}/usr/local/lib
mkdir -p ${ROOTFS_PATH}/opt/intel_nnpi/bin
mkdir -p ${ROOTFS_PATH}/opt/intel_nnpi/lib
mkdir -p ${ROOTFS_PATH}/opt/intel_nnpi/modules
mkdir -p ${ROOTFS_PATH}/opt/intel_nnpi/bit
# mkdir -p ${ROOTFS_PATH}/lib/modules/${KVER}/extra

add_line_to_file "FULL_STACK SPH_OS ${BUILD_CONFIGURATION} ${FULL_STACK_VER_TAG}" ${VERSION_PATH}
add_line_to_file "SPH_OS VANILLA ${VANILLA_VER_TAG}" ${VERSION_PATH}

add_line_to_file "PLATFORM_SW"  ${VERSION_PATH}
#platform sw
if [ "${BUILD_CONFIGURATION}" == "sph_sa" ]; then
	PLAT_SW_TAR_PATH_ARR=(${CARD_DRIVER_ARTIFACT} ${CARD_TEST_ARTIFACT} ${CARD_SDK_ARTIFACT} ${HOST_DRIVER_ARTIFACT} ${HOST_TEST_ARTIFACT} ${HOST_SDK_ARTIFACT})

    echo "create sdk directory"
    mkdir -p ${EXTRA_DIR}
    echo "unpack to sdk dir"
    echo ${REL_ART_PLAT_SW_BASE_PATH}/${HOST_SDK_ARTIFACT}
    echo ${REL_ART_PLAT_SW_BASE_PATH}/${CARD_SDK_ARTIFACT}
    echo ${REL_ART_INFERENCE_API_BASE_PATH}/${INFERENCE_API_HOST_INCLUDE}

    tar -xvf ${REL_ART_PLAT_SW_BASE_PATH}/${HOST_SDK_ARTIFACT} -C ${EXTRA_DIR}
    tar -xvf ${REL_ART_PLAT_SW_BASE_PATH}/${CARD_SDK_ARTIFACT} -C ${EXTRA_DIR}
    tar -xvf ${REL_ART_INFERENCE_API_BASE_PATH}/${INFERENCE_API_HOST_INCLUDE} -C ${EXTRA_DIR}
else
        if [ "${BUILD_FLAVOUR}" == "Debug" ]; then
           PLAT_SW_TAR_PATH_ARR=(${CARD_DRIVER_ARTIFACT} ${CARD_TEST_ARTIFACT} ${CARD_SDK_ARTIFACT})
        else
           PLAT_SW_TAR_PATH_ARR=(${CARD_DRIVER_ARTIFACT} ${CARD_SDK_ARTIFACT})
        fi
fi
#PLAT_SW_UNTAR_DEST_PATH=${ROOTFS_PATH}/sph_tmp/platform
#platform SW is untarred to /opt/sph/{bin,modules}
PLAT_SW_UNTAR_DEST_PATH=${ROOTFS_PATH}/
pushd ${REL_ART_PLAT_SW_BASE_PATH}
for tar_path in "${PLAT_SW_TAR_PATH_ARR[@]}"
do
	tar_file=${tar_path}
	filename=$(ls $tar_file)
	ver_file=$(basename -- "$filename")
	ver_file=$(echo "$ver_file" | sed 's/\.tar.gz//g')
	add_line_to_file $ver_file  ${VERSION_PATH}
	tar -xvzf  ${tar_file} -C ${PLAT_SW_UNTAR_DEST_PATH}
	check_success "$?" "tar -xvzf" "${tar_file}" 
done
popd
#move modules to their actual place in linux (/lib/modules/$KVER/extra)

find ${ROOTFS_PATH}/opt/intel_nnpi/bin -type f -exec chmod a+x {} \; 

PLAT_SW_KO_MODS_ARR=(sph_local sphcs nnpi_eth sphdrv)
for ko_mod in "${PLAT_SW_KO_MODS_ARR[@]}"
do
	add_line_to_file "extra/${ko_mod}.ko:" "${ROOTFS_PATH}/lib/modules/${KVER_REAL}/modules.dep"
done

pushd ${INFERENCE_API_ARTIFACT_PATH}
filename=$(ls $INFERENCE_API_DRIVER)
ver_file=$(basename -- "$filename")
add_line_to_file "INFERENCE_API"  ${VERSION_PATH}
ver_file=$(echo "$ver_file" | sed 's/\.tar.gz//g')
echo $ver_file
add_line_to_file $ver_file  ${VERSION_PATH}
tar -xvzf ${filename} -C ${ROOTFS_PATH}
check_success "$?" "tar -xvzf" "${filename}" 

#inference api
if [ "${BUILD_CONFIGURATION}" == "sph_sa" ]; then
	filename=$(ls $INFERENCE_API_TESTS)
	ver_file=$(basename -- "$filename")
	add_line_to_file "INFERENCE_API_TESTS"  ${VERSION_PATH}
	ver_file=$(echo "$ver_file" | sed 's/\.tar.gz//g')
	echo $ver_file
	add_line_to_file $ver_file  ${VERSION_PATH}
	tar -xvzf ${filename} -C ${ROOTFS_PATH}
	check_success "$?" "tar -xvzf" "${filename}" 

        filename=$(ls $INFERENCE_API_LIGHT_TESTS)
	ver_file=$(basename -- "$filename")
	add_line_to_file "INFERENCE_API_LIGHT_TESTS"  ${VERSION_PATH}
	ver_file=$(echo "$ver_file" | sed 's/\.tar.gz//g')
	echo $ver_file
	add_line_to_file $ver_file  ${VERSION_PATH}
	tar -xvzf ${filename} -C ${ROOTFS_PATH}
	check_success "$?" "tar -xvzf" "${filename}" 

	#/tmp/artifacts folder will stay in /tmp. The rest will move to /usr/local/lib and to /opt/sph/bin
	chmod 755 ${ROOTFS_PATH}/opt/intel_nnpi/bin/tests
	chmod 755 ${ROOTFS_PATH}/opt/intel_nnpi/bin/genericTests
	chmod 755 ${ROOTFS_PATH}/opt/intel_nnpi/artifacts
fi
popd

#firmware
add_line_to_file "FIRMWARE"  ${VERSION_PATH}

rm -rf ${ROOTFS_PATH}/lib/firmware/intel_nnpi
cd ${THIS_MANIFEST_BASE_PATH}
rm -rf runtime_asip_fw && rm -rf runtime_ivp_fw
./aipg_inference_validation-automation/tools/artifact_cli.py -d --from test_artifacts/runtime/asip_fw/  --to runtime_asip_fw/ -p latest=true
./aipg_inference_validation-automation/tools/artifact_cli.py -d --from test_artifacts/runtime/ivp_fw/  --to runtime_ivp_fw/ -p latest=true
pushd runtime_asip_fw && rename 's/image0/image5/' *
popd
pushd runtime_ivp_fw && rename 's/image0/image2/' *
popd
mkdir -p ${ROOTFS_PATH}/lib/firmware/intel_nnpi
mkdir -p ${ROOTFS_PATH}/sph_tmp/firmware
#TODO-FW has no version in its tar.gz
tar_file=${tar_path}
filename=$(ls $FIRMWARE_ARTIFACT)
ver_file=$(basename -- "$filename")
ver_file=$(echo "$ver_file" | sed 's/\.tar.gz//g')
add_line_to_file $ver_file  ${VERSION_PATH}
tar -xvzf  ${filename} -C ${ROOTFS_PATH}
check_success "$?" "tar -xvzf" "${filename}" 

cp -r ${RUNTIME_ASIP_FW} ${ROOTFS_PATH}/sph_tmp/
mv ${ROOTFS_PATH}/sph_tmp/runtime_asip_fw/*cve_image* ${ROOTFS_PATH}/lib/firmware/intel_nnpi
cp -r ${RUNTIME_IVP_FW} ${ROOTFS_PATH}/sph_tmp/
mv ${ROOTFS_PATH}/sph_tmp/runtime_ivp_fw/*cve_image* ${ROOTFS_PATH}/lib/firmware/intel_nnpi

#driver
add_line_to_file "ICE DRIVER KERNEL"  ${VERSION_PATH}
filename=$(ls $ICE_DRIVER_KERNEL_ARTIFACT_TAR_PATH)
ver_file=$(basename -- "$filename")
ver_file=$(echo "$ver_file" | sed 's/\.tar.gz//g')
add_line_to_file $ver_file  ${VERSION_PATH}

tar -xvzf ${filename} -C ${ROOTFS_PATH}
check_success "$?" "tar -xvzf" "${filename}" 

add_line_to_file "extra/intel_nnpi.ko:" "${ROOTFS_PATH}/lib/modules/${KVER_REAL}/modules.dep"
ver_file=$(basename -- "$ICE_DRIVER_USER_ARTIFACT")

add_line_to_file "ICE DRIVER USER"  ${VERSION_PATH}
filename=$(ls $ICE_DRIVER_USER_ARTIFACT)
ver_file=$(basename -- "$filename")
ver_file=$(echo "$ver_file" | sed 's/\.tar.gz//g')
add_line_to_file $ver_file  ${VERSION_PATH}

tar -xvzf $filename -C ${ROOTFS_PATH}
check_success "$?" "tar -xvzf" "${filename}" 

#driver_tests is moved to /opt/sph/bin, scenarios/ will stay at /sph_tmp/driver/driver_tests

filename=$(ls $ICE_DRIVER_USER_TESTS_ARTIFACT)
ver_file=$(basename -- "$filename")
ver_file=$(echo "$ver_file" | sed 's/\.tar.gz//g')
add_line_to_file $ver_file  ${VERSION_PATH}
tar -xvzf $filename -C ${ROOTFS_PATH}
check_success "$?" "tar -xvzf" "${filename}" 

#runtime 
tar -xvf ${RUNTIME_ARTIFACT} -C ${ROOTFS_PATH}
check_success "$?" "tar -xvf" "${RUNTIME_ARTIFACT}" 

ver_file=$(basename -- "$RUNTIME_ARTIFACT")
add_line_to_file "RUNTIME"  ${VERSION_PATH}
ver_file=$(echo "$ver_file" | sed 's/\.tar.gz//g')
add_line_to_file $ver_file  ${VERSION_PATH}

if [[ ( "${BUILD_CONFIGURATION}" == "sph_sa" ) ||  ( "${BUILD_CONFIGURATION}" == "sph_ep" && "${BUILD_FLAVOUR}" == "Debug" ) ]]; then
   tar -xvf ${RUNTIME_TEST} -C ${ROOTFS_PATH}
   check_success "$?" "tar -xvf" "${RUNTIME_TEST}" 
   ver_file=$(basename -- "$RUNTIME_TEST")
   add_line_to_file "RUNTIME_TEST"  ${VERSION_PATH}
   ver_file=$(echo "$ver_file" | sed 's/\.tar.gz//g')
   add_line_to_file $ver_file  ${VERSION_PATH}
   chmod +x ${ROOTFS_PATH}/opt/intel_nnpi/bin/sph_runtime
fi

tar -xvf ${VIRUS_RUNTIME_TEST} -C ${ROOTFS_PATH}
check_success "$?" "tar -xvf" "${VIRUS_RUNTIME_TEST}" 
ver_file=$(basename -- "$VIRUS_RUNTIME_TEST")
add_line_to_file "VIRUS_RUNTIME_TEST"  ${VERSION_PATH}
ver_file=$(echo "$ver_file" | sed 's/\.tar.gz//g')
add_line_to_file $ver_file  ${VERSION_PATH}

tar -xvf ${PTU_TOOL_ARTIFACT} -C ${ROOTFS_PATH}
check_success "$?" "tar -xvf" "${PTU_TOOL_ARTIFACT}"
ver_file=$(basename -- "$PTU_TOOL_ARTIFACT")
add_line_to_file "PTU_TOOL"  ${VERSION_PATH}
ver_file=$(echo "$ver_file" | sed 's/\.tar.gz//g')
add_line_to_file $ver_file  ${VERSION_PATH}

# Remove release notes
RELEASE_NOTES=${ROOTFS_PATH}/opt/intel_nnpi/bit/release_notes.txt
if [[ -f "${RELEASE_NOTES}" ]]; then
    echo "Remove release notes"
    rm ${RELEASE_NOTES}
fi

if [ "${BUILD_CONFIGURATION}" == "sph_sa" ]; then
	sed -i 's/sph_memalloc_placeholder/memalloc_sph_sa/' ${ROOTFS_PATH}/usr/local/bin/sph_platform_start 
else
	sed -i 's/sph_memalloc_placeholder/memalloc_sph_ep/' ${ROOTFS_PATH}/usr/local/bin/sph_platform_start 
fi

if [ "${BUILD_CONFIGURATION}" == "sph_sa" ]; then
	sed -i 's/sph_start_placeholder/start_sph_sa/' ${ROOTFS_PATH}/usr/local/bin/sph_platform_start 
else
	sed -i 's/sph_start_placeholder/start_sph_ep/' ${ROOTFS_PATH}/usr/local/bin/sph_platform_start 
fi
