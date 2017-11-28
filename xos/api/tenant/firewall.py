
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


from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework.reverse import reverse
from rest_framework import serializers
from rest_framework import generics
from rest_framework import status
from rest_framework.authentication import *
from core.models import *
from django.forms import widgets
from django.conf import settings
from xos.apibase import XOSListCreateAPIView, XOSRetrieveUpdateDestroyAPIView, XOSPermissionDenied
from api.xosapi_helpers import PlusModelSerializer, XOSViewSet, ReadOnlyField
from xos.logger import Logger, logging
from services.fwaas.models import FwService, Firewall, Rule
import json
import uuid
import traceback
import pool

logger = Logger(level=logging.INFO)
settings.DEBUG = False


class CsrfExemptSessionAuthentication(SessionAuthentication):
    def enforce_csrf(self, request):
        return  # To not perform the csrf check previously happening


def get_default_fw_service():
    fw_services = FwService.objects.all()
    if fw_services:
        return fw_services[0]
    return None


class FirewallSerializer(PlusModelSerializer):
    id = ReadOnlyField()
    owner = serializers.PrimaryKeyRelatedField(queryset=FwService.objects.all(), default=get_default_fw_service)

    class Meta:
        model = Firewall
        fields = ('id', 'owner', 'firewall_name', 'firewall_name', 'firewall_id', 'firewall_rules', 'slice_name', 'status', 'description')


class FirewallViewSet(XOSViewSet):
    authentication_classes = (CsrfExemptSessionAuthentication, BasicAuthentication)

    base_name = "firewalls"
    method_name = "firewalls"
    method_kind = "viewset"
    queryset = Firewall.objects.all()
    serializer_class = FirewallSerializer

    @classmethod
    def get_urlpatterns(self, api_path="^"):
        patterns = super(FirewallViewSet, self).get_urlpatterns(api_path=api_path)

        # firewall to demonstrate adding a custom endpoint
        patterns.append(self.detail_url("insert_rule/$", {"put": "update_insert_rule"}, "insert_rule"))
        patterns.append(self.detail_url("remove_rule/$", {"put": "update_remove_rule"}, "remove_rule"))

        return patterns

    def print_message_log(self, msg_type, http):
        if msg_type == "REQ":
            logger.info("###################################################")
            logger.info("[Server] <--- [Client]")
            logger.info("METHOD=%s" % http.method)
            logger.info("URI=%s" % http.path)
            logger.info("%s\n" % http.data)
        elif msg_type == "RSP":
            logger.info("[Server] ---> [Client]")
            logger.info("%s" % http)
            logger.info("Send http rsponse Success..\n")
        else:
            logger.error("Invalid msg_type(%s)" % msg_type)

    def get_rsp_body(self, fw_id):
        fw_info = Firewall.objects.get(firewall_id=fw_id)

        root_obj = {}
        fw_obj = {}
        fw_rule_list = []
        root_obj['firewall'] = fw_obj

        fw_obj['name'] = fw_info.firewall_name
        fw_obj['id'] = fw_info.firewall_id

        fw_obj['firewall_rules'] = fw_rule_list
        rules = fw_info.firewall_rules.split(',')
        for rule in rules:
            if rule != "":
                fw_rule_list.append(rule)

        fw_obj['status'] = fw_info.status
        fw_obj['description'] = fw_info.description

        return root_obj, fw_obj

    def update_firewall_info(self, fw_info, request):
        required_flag = True
        if request.method == "POST":
            if 'firewall_name' not in request.data or request.data["firewall_name"] == "":
                required_flag = False
            if 'firewall_rules' not in request.data or request.data["firewall_rules"] == "":
                required_flag = False
            if 'slice_name' not in request.data or request.data["slice_name"] == "":
                required_flag = False

        if not required_flag:
            logger.error("Mandatory fields not exist!")
            return None

        try:
            if 'firewall_name' in request.data and request.data["firewall_name"]:
                fw_info.firewall_name = request.data["firewall_name"]
            if 'firewall_id' in request.data and request.data["firewall_id"]:
                fw_info.firewall_id = request.data["firewall_id"]
            if 'firewall_rules' in request.data and request.data["firewall_rules"]:
                rules = ""
                for rule in request.data["firewall_rules"]:
                    rules += str(rule)
                    rules += ","
                rules = rules[:-1]
                fw_info.firewall_rules = rules
            if 'slice_name' in request.data and request.data["slice_name"]:
                fw_info.slice_name = request.data["slice_name"]
            if 'status' in request.data and request.data["status"]:
                fw_info.status = request.data["status"]
            if 'description' in request.data and request.data["description"]:
                fw_info.description = request.data["description"]

        except KeyError as err:
            logger.error("JSON Key error: %s" % str(err))
            return None

        fw_info.save(always_update_timestamp=True)

        return fw_info

    def check_fw_id(self, fw_id):
        try:
            fw = Firewall.objects.get(firewall_id=fw_id)
            return fw
        except Exception as err:
            logger.error("%s (firewall_id=%s)" % ((str(err), fw_id)))
            return None

    # GET: /api/tenant/firewalls
    def list(self, request):
        self.print_message_log("REQ", request)
        queryset = self.filter_queryset(self.get_queryset())

        root_obj = {}
        fw_obj_list = []
        root_obj['firewalls'] = fw_obj_list

        for fw in queryset:
            temp_obj, fw_obj = self.get_rsp_body(fw.firewall_id)
            fw_obj_list.append(fw_obj)

        self.print_message_log("RSP", root_obj)
        return Response(root_obj)

    # POST: /api/tenant/firewalls
    def create(self, request):
        self.print_message_log("REQ", request)

        fw_info = Firewall()
        fw_info.creator_id = 1

        if 'owner' in request.data and request.data["owner"]:
            fw_info.owner_id = request.data["owner"]
        else:
            try:
                service = Service.objects.get(name="fwaas")
                fw_info.owner_id = service.id
            except Exception as err:
                return Response("Error: name(fwaas) does not exist in core_service", status=status.HTTP_404_NOT_FOUND)

            # FIXME: Read from Config file
            # Because mount_data_sets information is not available with TOSCA
            slices = Slice.objects.filter(service_id=service.id)
            for slice in slices:
                if slice.mount_data_sets == "GenBank":
                    slice.mount_data_sets = "/etc/iptables/"
                    slice.save()

        if 'slice_name' in request.data and request.data["slice_name"]:
            tmp_slice_name = request.data["slice_name"]
            network_name = tmp_slice_name.split('_', 1)
            try:
                network = Network.objects.get(name=network_name[1])
                logger.info("network.id=%s" % network.id)
                fw_info.vip_subnet_id = network.id
            except Exception as err:
                err_str = "Error: network_name(%s) does not exist in Network table" % network_name[1]
                return Response(err_str, status=status.HTTP_404_NOT_FOUND)

        fw_info.firewall_id = str(uuid.uuid4())
        fw_info.status = "PENDING_CREATE"

        fw_info = self.update_firewall_info(fw_info, request)
        if fw_info is None:
            return Response("Error: Mandatory fields not exist!", status=status.HTTP_400_BAD_REQUEST)

        rsp_data, fw_obj = self.get_rsp_body(fw_info.firewall_id)

        self.print_message_log("RSP", rsp_data)
        return Response(rsp_data, status=status.HTTP_201_CREATED)

    # GET: /api/tenant/firewalls/{firewall_id}
    def retrieve(self, request, pk=None):
        self.print_message_log("REQ", request)

        if self.check_fw_id(pk) is None:
            return Response("Error: firewall_id does not exist in Firewall table", status=status.HTTP_404_NOT_FOUND)

        rsp_data, fw_obj = self.get_rsp_body(pk)

        self.print_message_log("RSP", rsp_data)
        return Response(rsp_data)

    # PUT: /api/tenant/firewalls/{firewall_id}
    def update(self, request, pk=None):
        self.print_message_log("REQ", request)

        fw_info = self.check_fw_id(pk)
        if fw_info is None:
            return Response("Error: firewall_id does not exist in Firewall table", status=status.HTTP_404_NOT_FOUND)

        fw_info = self.update_firewall_info(fw_info, request)
        if fw_info is None:
            return Response("Error: Mandatory fields not exist!", status=status.HTTP_400_BAD_REQUEST)

        rsp_data, fw_obj = self.get_rsp_body(pk)

        self.print_message_log("RSP", rsp_data)
        return Response(rsp_data)

    # DELETE: /api/tenant/firewalls/{firewall_id}
    def destroy(self, request, pk=None):
        self.print_message_log("REQ", request)

        fw_info = self.check_fw_id(pk)
        if fw_info is None:
            return Response("Error: firewall_id does not exist in Firewall table", status=status.HTTP_404_NOT_FOUND)

        ins = Instance.objects.get(id=fw_info.instance_id)
        ins.deleted = True
        ins.save()

        Firewall.objects.filter(firewall_id=pk).delete()
        Port.objects.filter(instance_id=fw_info.instance_id).delete()
        Tag.objects.filter(object_id=fw_info.instance_id).delete()

        self.print_message_log("RSP", "")
        return Response(status=status.HTTP_204_NO_CONTENT)

    # PUT: /api/tenant/firewalls/{firewall_id}/insert_rule
    def update_insert_rule(self, request, pk=None):
        self.print_message_log("REQ", request)

        required_flag = True
        if 'firewall_rule_id' not in request.data or request.data["firewall_rule_id"] == "":
            required_flag = False
        elif 'insert_before' not in request.data:
            required_flag = False
        elif 'insert_after' not in request.data:
            required_flag = False

        if not required_flag:
            return Response("Error: Mandatory fields not exist!", status=status.HTTP_400_BAD_REQUEST)

        fw_info = self.check_fw_id(pk)
        if fw_info is None:
            return Response("Error: firewall_id does not exist in Firewall table", status=status.HTTP_404_NOT_FOUND)

        if request.data["insert_before"] != "":
            rule_info = request.data["insert_before"]
        elif request.data["insert_after"] != "":
            rule_info = request.data["insert_after"]

        if request.data["insert_before"] != "" or request.data["insert_after"] != "":
            try:
                fw = Firewall.objects.get(firewall_id=pk, firewall_rules__contains=rule_info)
                rules = fw.firewall_rules.split(",")
                for idx, rule in enumerate(rules):
                    if rule == rule_info:
                        if request.data["insert_before"] != "":
                            rules.insert(idx, request.data["firewall_rule_id"])
                            break
                        elif request.data["insert_after"] != "":
                            rules.insert(idx+1, request.data["firewall_rule_id"])
                            break
                    if idx == len(rules)-1:
                        logger.error("firewall_rules(%s) does not exist in Firewall table" % rule_info)
                        return Response("Error: firewall_rules does not exist in Firewall table", status=status.HTTP_404_NOT_FOUND)

                new_rules = ""
                for idx in rules:
                    new_rules += str(idx)
                    new_rules += ","

                new_rules = new_rules[:-1]

                fw.firewall_rules = new_rules
                fw.save(always_update_timestamp=True)
            except Exception as err:
                logger.error("%s - firewall_rules(%s) does not exist in Firewall table" % ((str(err), rule_info)))
                return Response("Error: firewall_rules does not exist in Firewall table", status=status.HTTP_404_NOT_FOUND)

        else:
            try:
                fw = Firewall.objects.get(firewall_id=pk)
                fw.firewall_rules = "%s,%s" % (request.data["firewall_rule_id"], fw.firewall_rules)
                fw.save(always_update_timestamp=True)
            except Exception as err:
                logger.error("%s - firewall_rules(%s) does not exist in Firewall table" % ((str(err), rule_info)))
                return Response("Error: firewall_rules does not exist in Firewall table", status=status.HTTP_404_NOT_FOUND)

        rsp_data, fw_obj = self.get_rsp_body(pk)

        self.print_message_log("RSP", rsp_data)
        return Response(rsp_data)

    # PUT: /api/tenant/firewalls/{firewall_id}/remove_rule
    def update_remove_rule(self, request, pk=None):
        self.print_message_log("REQ", request)

        required_flag = True
        if 'firewall_rule_id' not in request.data or request.data["firewall_rule_id"] == "":
            return Response("Error: Mandatory fields not exist!", status=status.HTTP_400_BAD_REQUEST)

        fw = self.check_fw_id(pk)
        if fw is None:
            return Response("Error: firewall_id does not exist in Firewall table", status=status.HTTP_404_NOT_FOUND)

        rules = fw.firewall_rules.split(",")
        for idx, rule in enumerate(rules):
            if rule == request.data["firewall_rule_id"]:
                rules.remove(request.data["firewall_rule_id"])

        new_rules = ""
        for idx in rules:
            new_rules += str(idx)
            new_rules += ","

        new_rules = new_rules[:-1]
        fw.firewall_rules = new_rules
        fw.save(always_update_timestamp=True)

        rsp_data, fw_obj = self.get_rsp_body(pk)

        self.print_message_log("RSP", rsp_data)
        return Response(rsp_data)
