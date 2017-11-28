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


import uuid

from xosresource import XOSResource
from core.models import Service
from services.fwaas.models import Firewall, Rule


class FwaasFirewall(XOSResource):
    provides = "tosca.nodes.Firewall"
    xos_model = Firewall
    name_field = "service_specific_id"
    copyin_props = ("firewall_name", "firewall_id", "firewall_rules", "slice_name", "status", "description")

    def get_xos_args(self, throw_exception=True):
        args = super(FwaasFirewall, self).get_xos_args()

        # FwaasFirewall must always have a provider_service
        provider_name = self.get_requirement("tosca.relationships.TenantOfService", throw_exception=True)
        if provider_name:
            args["owner"] = self.get_xos_object(Service, throw_exception=True, name=provider_name)

        return args

    def get_existing_objs(self):
        args = self.get_xos_args(throw_exception=False)
        return Firewall.objects.filter(owner=args["owner"], service_specific_id=args["service_specific_id"])
        return []

    def can_delete(self, obj):
        return super(FwaasFirewall, self).can_delete(obj)


class FwaasRule(XOSResource):
    provides = "tosca.nodes.Rule"
    xos_model = Rule
    name_field = "rule_name"
    copyin_props = ("rule_name", "rule_id", "protocol", "src_ip", "src_port", "dst_ip", "dst_port", "ip_version", "action", "enabled", "description")

    def get_xos_args(self, throw_exception=True):
        args = super(FwaasRule, self).get_xos_args()

        if "rule_id" not in args:
            args["rule_id"] = str(uuid.uuid4())

        return args

    def can_delete(self, obj):
        return super(FwaasRule, self).can_delete(obj)
