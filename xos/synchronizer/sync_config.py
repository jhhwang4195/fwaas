
# Copyright 2017-present Open Networking Foundation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


import importlib
import os
import sys
import time
import datetime
import threading
import json

from xosconfig import Config
config_file = os.path.abspath(os.path.dirname(os.path.realpath(__file__)) + '/fwaas_config.yaml')
Config.init(config_file, 'synchronizer-config-schema.yaml')

sys.path.insert(0, "/opt/xos")
from synchronizers.new_base.modelaccessor import *
import fwaas_log as slog


def check_instance_status():
    while True:
        time.sleep(5)
        instances = Instance.objects.all()
        slog.info("instances.count = %s" % len(instances))

        for ins in instances:
            tag = ""
            provisioning_status = ""

            try:
                tag = Tag.objects.get(object_id=ins.id, name="chk_container_status")
            except Exception as err:
                slog.error("Error: object_id(%s) does not exist in Tag table (%s)" % (ins.id, str(err)))
                continue

            if ins.backend_code == 0:
                provisioning_status = "PENDING_UPDATE"

            elif ins.backend_code == 1:
                if tag.value == "":
                    provisioning_status = "PENDING_UPDATE"
                else:
                    try:
                        userdata = json.loads(tag.value)
                        create_timestamp = time.mktime(datetime.datetime.strptime(userdata['create_date'], "%Y-%m-%d %H:%M:%S").timetuple())
                        update_timestamp = time.mktime(datetime.datetime.strptime(userdata['update_date'], "%Y-%m-%d %H:%M:%S").timetuple())

                        if userdata['result'] == "Initialized":
                            provisioning_status = "PENDING_UPDATE"
                        elif userdata['expected_result'] != userdata['result'] and (float(update_timestamp) - float(create_timestamp)) > 30:
                            provisioning_status = "ERROR"
                        else:
                            provisioning_status = "ACTIVE"
                    except Exception as err:
                        slog.error("Error: json.loads() failed (%s)" % str(err))
            else:
                try:
                    userdata = json.loads(tag.value)
                    create_timestamp = time.mktime(datetime.datetime.strptime(userdata['create_date'], "%Y-%m-%d %H:%M:%S").timetuple())
                    update_timestamp = time.mktime(datetime.datetime.strptime(userdata['update_date'], "%Y-%m-%d %H:%M:%S").timetuple())

                    if (float(update_timestamp) - float(create_timestamp)) < 30:
                        provisioning_status = "PENDING_UPDATE"
                    else:
                        provisioning_status = "ERROR"
                except Exception as err:
                    slog.error("Error: json.loads() failed (%s)" % str(err))

            try:
                fw = Firewall.objects.get(tenantwithcontainer_ptr_id=ins.id)
                fw.status = provisioning_status
                fw.save()
                slog.info("id=%s, instance_name=%s, fw.status=%s"
                          % (ins.id, ins.instance_name, fw.status))
            except Exception as err:
                slog.error("Error: id(%s) does not exist in Loadbalancer table (%s)" % (ins.id, str(err)))


if __name__ == "__main__":
    models_active = False
    wait = False

    while not models_active:
        try:
            first_controller = Controller.objects.first()
            slog.debug("one of controller set: %s" % first_controller.name)
            first_image = Image.objects.first()
            slog.debug("one of image set     : %s" % first_image.name)
            models_active = True
        except Exception as e:
            slog.info(str(e))
            slog.info('Waiting for data model to come up before starting...')
            time.sleep(3)
            wait = True

    slog.debug("Data Model is active (first_controller: %s)" % first_controller)

    if wait:
        time.sleep(5)  # Safety factor, seeing that we stumbled waiting for the data model to come up.

    ins_thr = threading.Thread(target=check_instance_status)
    ins_thr.start()
