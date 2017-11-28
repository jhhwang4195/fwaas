
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
DB_CMD="docker exec -it swarmservice_xos_db_1 psql -U postgres -d xos -P pager=off -x -c"

######################################################
# delete fwaas model info
######################################################
$DB_CMD "delete from fwaas_firewall"
$DB_CMD "delete from fwaas_rule"

######################################################
# create fwaas model info
######################################################
./add_rule.sh 

# get rule_id
RESULT=`$DB_CMD "select * from fwaas_rule limit 1" | grep rule_id`
RULE_ID=`echo ${RESULT::-1} | awk '{print $3}'`

./add_firewall.sh $RULE_ID
