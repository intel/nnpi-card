#!/usr/bin/env python
"""
 * INTEL CONFIDENTIAL
 * Copyright 2017 Intel Corporation.
 * All Rights Reserved.
 *
 * The source code contained or described herein and all documents
 * related to the source code ("Material") are owned by Intel Corporation
 * or its suppliers or licensors. Title to the Material remains with Intel
 * Corporation or its suppliers and licensors. The Material may contain trade
 * secrets and proprietary and confidential information of Intel Corporation
 * and its suppliers and licensors, and is protected by worldwide copyright
 * and trade secret laws and treaty provisions. No part of the Material may
 * be used, copied, reproduced, modified, published, uploaded, posted,
 * transmitted, distributed, or disclosed in any way without Intel's prior
 * express written permission.
 * No license under any patent, copyright, trade secret or other intellectual of
 * property right is granted to or conferred upon you by disclosure or delivery
 * the Materials, either expressly, by implication, inducement, estoppel or otherwise.
 * Any license under such intellectual property rights must be express
 * and approved by Intel in writing.
"""
import os, getopt, tarfile, sys
from shutil import copyfile
from ConfigParser import SafeConfigParser, ConfigParser

buildsystem = os.path.abspath(os.path.join(__file__, '..', '..', '..', '..', '..', '..',
                                           'aipg_inference_validation-automation'))
if "ROOT_VAL_AUTOMATION" in os.environ:
    buildsystem = os.environ["ROOT_VAL_AUTOMATION"]
automation_path = os.path.abspath(os.path.join(__file__, '..', '..', '..', '..', '..'))
tools = os.path.abspath(os.path.join(automation_path, '..', 'aipg_inference_validation-automation'))
sys.path.insert(0, buildsystem)
sys.path.insert(1, tools)
from buildsystem.shared.enum import Enum
from tools.common_package_api.platform_common_pack import PlatformCommonPack, VanillaPack
from tools.common_package_api.utils import OsConfigs

def main():
    dest_path = os.path.join(__file__, '..', '..', '..', 'release_artifacts', 'packages')
    flavour = sys.argv[1]
    config = str(OsConfigs.VANILLA).lower()
    print sys.argv
    if len(sys.argv) >2:
        config = sys.argv[2]
        version = sys.argv[3]
        dest_path = sys.argv[4]
        print "config are {}, flavor {}, dest {} , version {} ,and value is  {} ".format(config, flavour, dest_path, version, str(OsConfigs.VANILLA).lower())
        if str(OsConfigs.VANILLA).lower() in config.lower():
            print "config are {}, flavor {}, dest {} , version {} ,and value is  {} ".format(config, flavour, dest_path, version, str(OsConfigs.VANILLA).lower())
            print "config is {} and value is  {} ".format(config, str(OsConfigs.VANILLA).lower())
            card = VanillaPack(flavour, config, dest_path, version)
            if card is not None:
                ret = card.set_init_conf()
                if not ret:
                    print
                    "Fail to set init conf the card payload"
                    return 1
        else:
            card = PlatformCommonPack(flavour, config, dest_path, version)
            if card is not None:
                if str(OsConfigs.VANILLA).lower() in config.lower():
                    ret = True
                else:
                    ret = card.full_stack_pack()
                    if ret is not True:
                        print "Fail to full_stack pack the card payload"
                        return 1
            else:
                print "Fail to set Packing object"
                return 1
    else:
        ret = True
    if ret:
        return 0
    else:
        return 1



if __name__ == "__main__":
    print "start main"
    ret = False
    ret = main()
    exit(ret)
