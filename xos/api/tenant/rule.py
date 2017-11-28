
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
import time
import threading

logger = Logger(level=logging.INFO)
settings.DEBUG = False


class CsrfExemptSessionAuthentication(SessionAuthentication):
    def enforce_csrf(self, request):
        return  # To not perform the csrf check previously happening


class RuleSerializer(PlusModelSerializer):
    id = ReadOnlyField()

    class Meta:
        model = Rule
        fields = ('id', 'rule_name', 'rule_id', 'protocol', 'src_ip', 'src_port', 'dst_ip', 'dst_port', 'ip_version', 'action', 'enabled', 'description')


class RuleViewSet(XOSViewSet):
    authentication_classes = (CsrfExemptSessionAuthentication, BasicAuthentication)

    base_name = "firewall_rules"
    method_name = "firewall_rules"
    method_kind = "viewset"
    queryset = Rule.objects.all()
    serializer_class = RuleSerializer

    @classmethod
    def get_urlpatterns(self, api_path="^"):
        patterns = super(RuleViewSet, self).get_urlpatterns(api_path=api_path)

        return patterns

    def update_firewall_model(self, rule_id):
        fws = Firewall.objects.filter(firewall_rules__contains=rule_id)

        for fw in fws:
            logger.info("Update Firewall(%s) Rule" % fw)
            fw.save(always_update_timestamp=True)

        if fws.count() == 0:
            logger.info("firewall_rules does not exist in Firewall table (firewall_rules=%s)" % rule_id)

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

    def get_rsp_body(self, rule_id):
        rule = Rule.objects.get(rule_id=rule_id)

        root_obj = {}
        rule_obj = {}
        root_obj['firewall_rule'] = rule_obj

        rule_obj['name'] = rule.rule_name
        rule_obj['id'] = rule.rule_id
        rule_obj['protocol'] = rule.protocol
        rule_obj['source_ip_address'] = rule.src_ip
        rule_obj['source_port'] = rule.src_port
        rule_obj['destination_ip_address'] = rule.dst_ip
        rule_obj['destination_port'] = rule.dst_port
        rule_obj['ip_version'] = rule.ip_version
        rule_obj['action'] = rule.action
        rule_obj['enabled'] = rule.enabled
        rule_obj['description'] = rule.description

        return root_obj, rule_obj

    def update_rule_info(self, rule, request):
        required_flag = True
        if request.method == "POST":
            if 'rule_name' not in request.data or request.data["rule_name"] == "":
                required_flag = False
            if 'protocol' not in request.data or request.data["protocol"] == "":
                required_flag = False
            if 'action' not in request.data or request.data["action"] == "":
                required_flag = False

        if not required_flag:
            logger.error("Mandatory fields not exist!")
            return None

        try:
            if 'rule_name' in request.data and request.data["rule_name"]:
                rule.rule_name = request.data["rule_name"]
            if 'rule_id' in request.data and request.data["rule_id"]:
                rule.rule_id = request.data["rule_id"]
            if 'protocol' in request.data and request.data["protocol"]:
                rule.protocol = request.data["protocol"]
            if 'src_ip' in request.data and request.data["src_ip"]:
                rule.src_ip = request.data["src_ip"]
            if 'src_port' in request.data and request.data["src_port"]:
                rule.src_port = request.data["src_port"]
            if 'dst_ip' in request.data and request.data["dst_ip"]:
                rule.dst_ip = request.data["dst_ip"]
            if 'dst_port' in request.data and request.data["dst_port"]:
                rule.dst_port = request.data["dst_port"]
            if 'ip_version' in request.data and request.data["ip_version"]:
                rule.ip_version = request.data["ip_version"]
            if 'action' in request.data and request.data["action"]:
                rule.action = request.data["action"]
            if 'enabled' in request.data:
                rule.enabled = request.data["enabled"]
            if 'description' in request.data and request.data["description"]:
                rule.description = request.data["description"]
        except KeyError as err:
            logger.error("JSON Key error: %s" % str(err))
            return None

        rule.save()
        return rule

    def check_rule_id(self, rule_id):
        try:
            rule = Rule.objects.get(rule_id=rule_id)
            return rule
        except Exception as err:
            logger.error("%s (rule_id=%s)" % ((str(err), rule_id)))
            return None

    # GET: /api/tenant/firewall_rules
    def list(self, request):
        self.print_message_log("REQ", request)
        queryset = self.filter_queryset(self.get_queryset())

        root_obj = {}
        rule_list = []
        root_obj['firewall_rules'] = rule_list

        for rule in queryset:
            temp_obj, rule_obj = self.get_rsp_body(rule.rule_id)
            rule_list.append(rule_obj)

        self.print_message_log("RSP", root_obj)
        return Response(root_obj)

    # POST: /api/tenant/firewall_rules
    def create(self, request):
        self.print_message_log("REQ", request)

        rule = Rule()
        rule.rule_id = str(uuid.uuid4())

        rule = self.update_rule_info(rule, request)
        if rule is None:
            return Response("Error: Mandatory fields not exist!", status=status.HTTP_400_BAD_REQUEST)

        rsp_data, rule_obj = self.get_rsp_body(rule.rule_id)

        rule_thr = threading.Thread(target=self.update_firewall_model, args=(rule.rule_id,))
        rule_thr.start()

        self.print_message_log("RSP", rsp_data)
        return Response(rsp_data, status=status.HTTP_201_CREATED)

    # GET: /api/tenant/firewall_rules/{rule_id}
    def retrieve(self, request, pk=None):
        self.print_message_log("REQ", request)

        if self.check_rule_id(pk) is None:
            return Response("Error: rule_id does not exist in Rule table", status=status.HTTP_404_NOT_FOUND)

        rsp_data, rule_obj = self.get_rsp_body(pk)

        self.print_message_log("RSP", rsp_data)
        return Response(rsp_data)

    # PUT: /api/tenant/firewall_rules/{rule_id}
    def update(self, request, pk=None):
        self.print_message_log("REQ", request)

        rule = self.check_rule_id(pk)
        if rule is None:
            return Response("Error: rule_id does not exist in Rule table", status=status.HTTP_404_NOT_FOUND)

        rule = self.update_rule_info(rule, request)
        if rule is None:
            return Response("Error: Mandatory fields not exist!", status=status.HTTP_400_BAD_REQUEST)

        rsp_data, rule_obj = self.get_rsp_body(pk)

        rule_thr = threading.Thread(target=self.update_firewall_model, args=(pk,))
        rule_thr.start()

        self.print_message_log("RSP", rsp_data)
        return Response(rsp_data)

    # DELETE: /api/tenant/firewall_rules/{rule_id}
    def destroy(self, request, pk=None):
        self.print_message_log("REQ", request)

        rule = self.check_rule_id(pk)
        if rule is None:
            return Response("Error: rule_id does not exist in Rule table", status=status.HTTP_404_NOT_FOUND)

        rule_thr = threading.Thread(target=self.update_firewall_model, args=(pk,))
        rule_thr.start()

        Rule.objects.filter(rule_id=pk).delete()

        self.print_message_log("RSP", "")
        return Response(status=status.HTTP_204_NO_CONTENT)
