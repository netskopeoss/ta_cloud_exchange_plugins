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

CRE LDAP Constants module.
"""

PLUGIN_NAME = "LDAP"
PLATFORM_NAME = "LDAP"
PLUGIN_VERSION = "1.0.0"
MODULE_NAME = "CRE"
TIMEOUT = 300
VALIDATION_TIMEOUT = 60
PLATFORM_NAME = "LDAP"
PAGE_SIZE = 10000
DEFAULT_WAIT_TIME = 60
MAX_RETRIES = 3
GROUP_REGEX = "(CN=)|(DC=)|(OU=)|(O=)|(UID=)|(C=)|(SN=)|(L=)|(ST=)|(STREET=)"
IP_REGEX = r"^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$"  # noqa
DNA_REGEX = r"^((?!-))(xn--)?[A-Za-z0-9][A-Za-z0-9-_]{0,61}[A-Za-z0-9]{0,1}\.(xn--)?([A-Za-z0-9\-]{1,61}|[A-Za-z0-9-]{1,30}\.[A-Za-z]{2,})$"  # noqa
USER_SEARCH_FILTER = (
    "(|(objectClass=person)(objectClass=inetOrgPerson)(objectClass=User))"
)
USER_PRINCIPAL_NAME = "User Principal Name"
EMAIL_FIELD = "Email Address"
USER_MAPPING = {
    "User Principal Name": {
        "key": "attributes.userPrincipalName",
    },
    "Email Address": {"key": "attributes.mail"},
    "Distinguished Name (DN)": {"key": "attributes.distinguishedName"},
    "User Name": {"key": "attributes.name"},
    "User Groups": {"key": "attributes.memberOf", "transformation": "list"},
}
