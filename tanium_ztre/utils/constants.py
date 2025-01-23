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

CRE Tanium Plugin constants.
"""
DEVICE_PAGE_COUNT = 5000
MODULE_NAME = "CRE"
PLATFORM_NAME = "Tanium"
PLUGIN_VERSION = "1.0.0"
DEFAULT_WAIT_TIME = 60
MAX_API_CALLS = 4
DEVICE_FIELD_MAPPING = {
   "Device ID": {"key": "node.id"},
   "Device Name": {"key": "node.name"},
   "Computer ID": {"key": "node.computerID"},
   "System ID": {"key": "node.systemUUID"},
   "Domain Name": {"key": "node.domainName"},
   "Serial Number": {"key": "node.serialNumber"},
   "Manufacturer": {"key": "node.manufacturer"},
   "IP Address": {"key": "node.ipAddress"},
   "Device User Name": {"key": "node.primaryUser.name"},
   "Device User Email": {"key": "node.primaryUser.email"},
   "OS": {"key": "node.os.name"},
   "OS Platform": {"key": "node.os.platform"},
   "OS Generation": {"key": "node.os.generation"},
}
TANIUM_GRAPHQL_QUERY = {
   "query": 'query getEndpoints($after: Cursor, $first: Int) { \
   endpoints(after: $after, first: $first) \
   { edges { node {    id    name    computerID    systemUUID \
   domainName    serialNumber    manufacturer    ipAddress    ipAddresses \
   macAddresses    primaryUser {        name        email    } \
   os {        name        platform        generation    } \
   sensorReadings(sensors: [{name: "Risk Vectors", \
   columns: ["Endpoint Score", "Risk Score", "Asset Criticality"]}]) { \
   columns {   name   values   }   } \
   installedApplications {        name    }    }    } \
   pageInfo{    hasNextPage    hasPreviousPage    startCursor \
   endCursor } totalRecords } }'
}
RISK_INFO_FIELDS = {
   "Risk Score": "Risk Score",
   "Endpoint Score": "Risk Score Level",
   "Asset Criticality": "Asset Criticality"
}
