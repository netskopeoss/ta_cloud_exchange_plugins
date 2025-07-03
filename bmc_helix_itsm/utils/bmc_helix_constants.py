"""
BSD 3-Clause License

Copyright (c) 2021, Netskope OSS
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its
   contributors may be used to endorse or promote products derived from
   this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

BMC Helix ITSM Constants."""


PLATFORM_NAME = "BMC Helix ITSM"
MODULE_NAME = "CTO"
PLUGIN_VERSION = "2.0.0"
MAX_RETRIES = 4
DEFAULT_WAIT_TIME = 60
INCIDENT_PAGE_SIZE = 250
GROUPS_PAGE_SIZE = 500

LOGIN_URL = "api/jwt/login"
TASK_URL = "api/arsys/v1/entry/HPD:IncidentInterface_Create"
GET_TASK_URL = "api/arsys/v1/entry/HPD:IncidentInterface_Create"
INCIDENT_FIELDS_URL = "api/arsys/v1.0/fields/HPD:IncidentInterface_Create"
LIST_GROUPS_URL = "api/arsys/v1/entry/CTM:Support Group"

UPDATE_FIELDS_LIST = []
INCIDENT_REQUIRED_FIELDS_VALUES = {
   "Status": [
      "New",
      "Assigned",
      "In Progress",
      "Pending",
      "Resolved",
      "Closed",
      "Cancelled"
   ],
   "Impact": [
      "1-Extensive/Widespread",
      "2-Significant/Large",
      "3-Moderate/Limited",
      "4-Minor/Localized"
   ],
   "Urgency": [
      "1-Critical",
      "2-High",
      "3-Medium",
      "4-Low"
   ],
   "Service_Type": [
      "User Service Restoration",
      "User Service Request",
      "Infrastructure Restoration",
      "Infrastructure Event",
      "Security Incident"
   ],
   "Reported Source": [
      "Email",
      "Chat",
      "Web",
      "BMC Impact Manager Event",
      "External Escalation",
      "Walk In",
      "Phone",
      "Direct Input",
      "Other",
      "Systems Management",
      "Self Service",
      "Fax",
      "Voice Mail"
   ],
   "First_Name": [],
   "Last_Name": [],
   "Description": [],
}
