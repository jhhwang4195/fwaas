
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


import os
import sys
import json
import collections
import time
import fwaas_log as slog

from datetime import datetime
from synchronizers.new_base.SyncInstanceUsingAnsible import SyncInstanceUsingAnsible
from synchronizers.new_base.modelaccessor import *

parentdir = os.path.join(os.path.dirname(__file__), "..")
sys.path.insert(0, parentdir)


class SyncFirewall(SyncInstanceUsingAnsible):
    provides = [Firewall]
    observes = Firewall
    requested_interval = 0
    template_name = "firewall_playbook.yaml"
    service_key_name = "/opt/xos/synchronizers/fwaas/fwaas_private_key"

    watches = [ModelLink(ServiceDependency, via='servicedependency'), ModelLink(ServiceMonitoringAgentInfo, via='monitoringagentinfo')]

    def __init__(self, *args, **kwargs):
        super(SyncFirewall, self).__init__(*args, **kwargs)

    def convert_unicode_to_str(self, data):
        if isinstance(data, basestring):
            return str(data)
        elif isinstance(data, collections.Mapping):
            return dict(map(self.convert_unicode_to_str, data.iteritems()))
        elif isinstance(data, collections.Iterable):
            return type(data)(map(self.convert_unicode_to_str, data))
        else:
            return data

    # Gets the attributes that are used by the Ansible template but are not
    # part of the set of default attributes.
    def get_extra_attributes(self, o):
        slog.info("===============================================================")
        slog.info("instance_name=%s, instance_id=%d, instance_uuid=%s"
                  % (o.instance.instance_name, o.instance_id, o.instance.instance_uuid))

        try:
            tags = Tag.objects.filter(object_id=o.instance.id)

            if not len(tags):
                userdata = {}
                userdata['create_date'] = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(time.time()))
                userdata['update_date'] = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(time.time()))
                userdata['command'] = "iptables --version"
                userdata['expected_result'] = "iptables v1.6.1"
                userdata['result'] = "Initialized"

                tag = Tag(service=o.instance.slice.service,
                          content_type=o.instance.self_content_type_id,
                          object_id=o.instance.id,
                          name="chk_container_status",
                          value=json.dumps(userdata))

                tag.save()
        except Exception as e:
            slog.error("Instance.objects.get() failed - %s" % str(e))

        fields = {}
        fields['instance_id'] = o.instance.id
        fields['update_time'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        fields["baremetal_ssh"] = True

        firewall = {}
        firewall['firewall_id'] = o.firewall_id
        firewall['firewall_name'] = o.firewall_name
        fields['firewall'] = json.dumps(firewall, indent=4)

        try:
            root_obj = {}
            rule_list = []
            root_obj['rules'] = rule_list

            rules = o.firewall_rules.split(',')
            for rule in rules:
                try:
                    obj = Rule.objects.get(rule_id=rule)
                    rule_obj = {}
                    rule_obj['rule_name'] = obj.rule_name
                    rule_obj['rule_id'] = obj.rule_id
                    rule_obj['protocol'] = obj.protocol
                    rule_obj['src_ip'] = obj.src_ip
                    rule_obj['src_port'] = obj.src_port
                    rule_obj['dst_ip'] = obj.dst_ip
                    rule_obj['dst_port'] = obj.dst_port
                    rule_obj['action'] = obj.action
                    rule_obj['enabled'] = obj.enabled
                    rule_list.append(rule_obj)
                except Exception as err:
                    slog.error("%s (rule_id=%s)" % ((str(err), rule)))

            fields['rules'] = json.dumps(root_obj, indent=4)

            slog.info(">>>>> Rule")
            slog.info("%s" % json.dumps(root_obj, indent=4))
        except Exception as e:
            slog.error("Rule.objects.get() failed - %s" % str(e))

        fields = self.convert_unicode_to_str(fields)
        return fields

    def delete_record(self, port):
        # Nothing needs to be done to delete an firewallservice; it goes away
        # when the instance holding the firewallservice is deleted.
        pass
