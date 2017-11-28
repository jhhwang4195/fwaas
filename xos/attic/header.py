
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


# models.py - Firewall Models

from core.models import Service, XOSBase, TenantWithContainer
from django.db import transaction
from django.db.models import *

SERVICE_NAME = 'fwaas'
SERVICE_NAME_VERBOSE = 'Firewall-as-a-Service'
SERVICE_NAME_VERBOSE_PLURAL = 'Firewall-as-a-Service'
SERVICE_INSTANCE_NAME_VERBOSE = 'Firewall'
SERVICE_INSTANCE_VERBOSE_PLURAL = 'Firewalls'
