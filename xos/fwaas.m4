
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


tosca_definitions_version: tosca_simple_yaml_1_0

# compile this with "m4 fwaas.m4 > fwaas.yaml"

# include macros
include(macros.m4)

node_types:
    tosca.nodes.FwService:
        derived_from: tosca.nodes.Root
        description: >
            Firewall Service
        capabilities:
            xos_base_service_caps
        properties:
            xos_base_props
            xos_base_service_props
            service_name:
                type: string
                required: false

    tosca.nodes.Firewall:
        derived_from: tosca.nodes.Root
        description: >
            A ServiceInstance of firewall
        properties:
            xos_base_tenant_props
            firewall_name:
                type: string
                required: false
            firewall_id:
                type: string
                required: false
            firewall_rules:
                type: string
                required: false
            slice_name:
                type: string
                required: false
            status:
                type: string
                required: false
            description:
                type: string
                required: false

    tosca.nodes.Rule:
        derived_from: tosca.nodes.Root
        description: >
            Rule of firewall
        properties:
            xos_base_props
            rule_name:
                type: string
                required: false
            rule_id:
                type: string
                required: false
            protocol:
                type: string
                required: false
            src_ip:
                type: string
                required: false
            src_port:
                type: string
                required: false
            dst_ip:
                type: string
                required: false
            dst_port:
                type: string
                required: false
            ip_version:
                type: integer
                required: false
            action:
                type: string
                required: false
            enabled:
                type: boolean
                required: false
            description:
                type: string
                required: false
