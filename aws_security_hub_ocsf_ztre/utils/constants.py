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

CRE AWS Security Hub OCSF Plugin constants.
"""

PLATFORM_NAME = "AWS Security Hub OCSF"
MODULE_NAME = "CRE"
PLUGIN_VERSION = "1.0.0"
MAXIMUM_CE_VERSION = "5.1.2"
BATCH_SIZE = 100
DATE_FORMAT = "%Y-%m-%dT%H:%M:%S.%f"
AUTHENTICATION_METHODS = [
    "aws_iam_roles_anywhere",
    "deployed_on_aws",
]
RETRY_ATTEMPTS = 3
RETRY_MODE = "standard"

REGIONS = [
    "us-east-2",
    "us-east-1",
    "us-west-1",
    "us-west-2",
    "af-south-1",
    "ap-east-1",
    "ap-south-1",
    "ap-northeast-3",
    "ap-northeast-2",
    "ap-southeast-1",
    "ap-southeast-2",
    "ap-northeast-1",
    "ca-central-1",
    "cn-north-1",
    "cn-northwest-1",
    "eu-central-1",
    "eu-west-1",
    "eu-west-2",
    "eu-south-1",
    "eu-west-3",
    "eu-north-1",
    "me-south-1",
    "sa-east-1",
    "ap-south-2",
    "ap-southeast-3",
    "eu-south-2",
    "eu-central-2",
    "me-central-1",
    "ca-west-1",
    "ap-southeast-4",
    "il-central-1",
    "ap-southeast-7",
    "ca-west-1",
    "ap-southeast-5",
    "mx-central-1"
]
DEVICE_FIELD_MAPPING = {
    "Finding ID": {"key": "finding_info.uid"},
    "Private IP": {
        "key": "private_ip_address", "context": "network_interface"
    },
    "Public IP": {"key": "public_ip", "context": "network_interface"},
    "Region": {"key": "region", "context": "resource"},
    "Resource Name": {"key": "name", "context": "resource"},
    "Resource UID": {"key": "uid", "context": "resource"},
    "Resource Tags": {"key": "data.tags", "context": "resource"},
    "Subnet ID": {"key": "subnet_id", "context": "network_interface"},
    "VPC ID": {"key": "vpc_id", "context": "network_interface"},
    "Severity": {"key": "severity"},
    "Product Name": {"key": "metadata.product.name"},
    "Finding Title": {"key": "finding_info.title"},
    "Finding Description": {"key": "finding_info.desc"},
    "First Seen": {"key": "finding_info.first_seen_time_dt"},
    "Last Seen": {"key": "finding_info.modified_time_dt"},
    "Finding Class": {"key": "class_name"}
}
USER_AGENT = "APN/1.1 (ahq9d89xj9gspapczzdb59goq)"
