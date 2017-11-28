
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


#!/bin/bash

source ./config.sh

if [[ "$#" -ne 1 ]]; then
    echo "Syntax: $0 <rule_id>"
    exit -1
fi

RULE_ID=$1

DATA=$(cat <<EOF
{
    "rule_name": "update_rule",
    "protocol": "udp",
    "src_ip": "192.168.10.12",
    "src_port": 12346,
    "dst_ip": "192.168.10.13",
    "dst_port": 81,
    "ip_version": 4,
    "action": "allow",
    "enabled": true,
    "description": "update_rule"
}
EOF
)

curl -H "Accept: application/json; indent=4" -H "Content-Type: application/json" -u $AUTH -X PUT -d "$DATA" $HOST/api/tenant/firewall_rules/$RULE_ID/
