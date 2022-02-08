# coding=utf-8
# --------------------------------------------------------------------------------------------------
# ThreatQuotient Proprietary and Confidential
# Copyright ©2020 ThreatQuotient, Inc. All rights reserved.
#
# NOTICE: All information contained herein, is, and remains the property of ThreatQuotient, Inc.
# The intellectual and technical concepts contained herein are proprietary to ThreatQuotient, Inc.
# and its suppliers and may be covered by U.S. and Foreign Patents, patents in process, and are
# protected by trade secret or copyright law.
#
# Dissemination of this information or reproduction of this material is strictly forbidden unless
# prior written permission is obtained from ThreatQuotient, Inc.
# --------------------------------------------------------------------------------------------------

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

from datetime import datetime
import json
from logging import getLogger
import os
import random
import re

import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning

# import all of the child modules so consumers can easily access them
from . import adversary  # NOQA
from . import file  # NOQA
from . import authentication
from . import event  # NOQA
from . import exceptions
from . import indicator  # NOQA
from . import bulkindicator  # NOQA
from . import signature  # NOQA
from . import source  # NOQA
from . import operation  # NOQA
from . import bulksignature  # NOQA
from . import advanced_search  # NOQA
from . import feed  # NOQA
from . import threat_library  # NOQA

# reexport some commonly used types
from .adversary import Adversary  # NOQA
from .file import File  # NOQA
from .event import Event  # NOQA
from .indicator import Indicator  # NOQA
from .bulkindicator import BulkIndicator  # NOQA
from .signature import Signature  # NOQA
from .source import Source  # NOQA
from .operation import Operation
from .bulksignature import BulkSignature  # NOQA
from .advanced_search import AdvancedSearch  # NOQA
from .feed import Feed  # NOQA
from .threat_library import ThreatLibrary  # NOQA

from netskope.common.utils import add_user_agent

__all__ = [
    # submodules
    "authentication",
    "event",
    "exceptions",
    "indicator",
    "signature",
    # types
    "Adversary",
    "File",
    "Event",
    "Indicator",
    "BulkIndicator",
    "Signature" "Source" "Threatq",
    "Operation",
    "BulkSignature",
    "AdvancedSearch" "Feed",
    "ThreatLibrary",
    # constants
    "VERSION",
]

_logger = getLogger(__name__)

VERSION = "1.8.0"

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


class Threatq(object):
    """A connection to the ThreatQuotient API.
    The auth and private parameters are passed directly to a new
    :py:class:`~threatqsdk.authentication.TokenHolder` instance.
    See the documentation for
    :py:class:`~threatqsdk.authentication.TokenHolder` for information
    about the usage and expected format of these parameters.

    Unless otherwise stated, any method in this class can raise a
    :py:class:`~threatqsdk.exceptions.APIError` when the API returns an
    error, or a :py:class:`~requests.exceptions.HTTPError` if a non-2XX
    status code is recieved from the API.

    :param str threatq_host: Hostname of the ThreatQuotient
        possibly including the protocol (must be https)
    :param bool verify: True if we should verify the SSL certificate
        of the deployment
    :param str proxy: Proxy to use, or None if no proxy should be used.
        In the format ``https://host.name:port``
    """

    def __init__(
        self, threatq_host, auth, private=False, verify=False, proxy=None
    ):

        self.statusinfo = None

        host_match = re.compile(r"^(\w+://)?([A-Z\d\-\.:]+)", re.IGNORECASE)
        host = host_match.match(threatq_host)
        if host is None:
            raise ValueError("Failed to parse host string")

        host = host.groups()
        if host[0] is not None and host[0] != "https://":
            msg = "Invalid protocol for host: {}. Only https is supported"
            raise ValueError(msg.format(host[0]))
        threatq_host = "https://" + host[1]

        self.threatq_host = threatq_host
        self.session = requests.Session()
        if proxy is not None:
            self.session.proxies = {"https": proxy}
        self.session.verify = verify

        self.auth = authentication.TokenHolder(
            threatq_host, auth, private, self.session
        )

    def now(self):
        """Get the current time in the string format that the TQ API expects"""
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def get(self, endpoint, withp=None, params=None):
        """ Make an authenticated ``GET`` request

        :param str endpoint: The endpoint to make a get request of.
        :param str withp: ``withp`` properties.
        :param dict params: Dictionary of URL parameters.
            Parameter names and values will be encoded for you.

        :raises:
            :py:class:`~threatqsdk.exceptions.APIError` if the API \
                response does not contains an ``errors`` property
            :py:class:`~requests.exceptions.HTTPError` if the API \
                returns a status code outside of the range [200, 299]

        :returns: JSON-decoded API response
        """
        if self.auth.is_token_expired():
            self.auth.refresh()

        if withp:
            if params is None:
                params = {}
            params["with"] = withp

        if endpoint[0] != "/":
            endpoint = "/" + endpoint

        r = self.session.get(
            self.threatq_host + endpoint,
            headers=add_user_agent(
                {"Authorization": "Bearer %s" % self.auth.accesstoken}
            ),
            params=params,
        )
        r.raise_for_status()

        res = r.json()
        if "errors" in res:
            raise exceptions.APIError(r)

        return res

    def put(self, endpoint, data=None, params=None):
        """ Make an authenticated ``PUT`` request.

        :param str endpoint: The endpoint to hit
        :param dict data: Dictionary of data.
            Will be automatically serialized with `json.dumps`
        :param dict params: Dictionary of URL parameters.
            Parameter names and values will be encoded for you.

        :raises:
            :py:class:`~threatqsdk.exceptions.APIError` if the API \
                response does not contains an ``errors`` property
            :py:class:`~requests.exceptions.HTTPError` if the API \
                returns a status code outside of the range [200, 299]

        :returns: JSON-decoded API response
        """
        if self.auth.is_token_expired():
            self.auth.refresh()

        if endpoint[0] != "/":
            endpoint = "/" + endpoint

        r = self.session.put(
            self.threatq_host + endpoint,
            headers=add_user_agent(
                {
                    "Authorization": "Bearer %s" % self.auth.accesstoken,
                    "content-type": "application/json",
                }
            ),
            data=json.dumps(data),
            params=params,
        )
        r.raise_for_status()

        res = r.json()
        if "errors" in res:
            raise exceptions.APIError(r)

        return res

    def delete(self, endpoint):
        """ Make an authenticated ``DELETE`` request.

        :param str endpoint: The endpoint to hit

        :raises:
            :py:class:`~threatqsdk.exceptions.APIError` if the API \
                response does not contains an ``errors`` property
            :py:class:`~requests.exceptions.HTTPError` if the API \
                returns a status code outside of the range [200, 299]

        :returns: JSON-decoded API response
        """

        if self.auth.is_token_expired():
            self.auth.refresh()

        if endpoint[0] != "/":
            endpoint = "/" + endpoint

        r = self.session.delete(
            self.threatq_host + endpoint,
            headers=add_user_agent(
                {"Authorization": "Bearer %s" % self.auth.accesstoken}
            ),
        )

        r.raise_for_status()
        return

    def post(self, endpoint, data=None, files=None, params=None):
        """ Make an authenticated ``POST`` request.

        :param str endpoint: The endpoint to hit
        :param dict data: POST data
        :param dict params: Dictionary of URL parameters.
            Parameter names and values will be encoded for you.

        :raises:
            :py:class:`~threatqsdk.exceptions.APIError` if the API \
                response does not contains an ``errors`` property
            :py:class:`~requests.exceptions.HTTPError` if the API \
                returns a status code outside of the range [200, 299]

        :returns: JSON-decoded API response
        """

        if self.auth.is_token_expired():
            self.auth.refresh()

        if endpoint[0] != "/":
            endpoint = "/" + endpoint

        if files:
            r = self.session.post(
                self.threatq_host + endpoint,
                headers=add_user_agent(
                    {
                        "Authorization": "Bearer %s" % self.auth.accesstoken,
                    }
                ),
                data=data,
                files=files,
                params=params,
            )
        else:
            r = self.session.post(
                self.threatq_host + endpoint,
                headers=add_user_agent(
                    {
                        "Authorization": "Bearer %s" % self.auth.accesstoken,
                        "content-type": "application/json",
                    }
                ),
                data=json.dumps(data),
                params=params,
            )
        r.raise_for_status()

        res = r.json()
        if "errors" in res:
            raise exceptions.APIError(r)

        return res

    def getproxy(self):
        return self.get("/api/configuration/proxy")

    def getindicatorbyid(self, iid, withp=None):
        """Get an indicator by ID, possibly including some additional
        information specified by `withp`

        :param int iid: Integer ID of the indicator

        :returns: JSON decoded dict with indicator data
        """
        return self.get("/api/indicators/%i" % iid, withp=withp)

    def addattributebyid(self, iid, key, value):
        """Get add an attribute to an indicator using the indicator
        ID.

        :param int iid: Integer ID of the indicator
        :param str key: Attribute key name
        :param str value: Attribute value

        :returns: ID of the created attribute, or None if no attribute was
            created
        """
        res = self.post(
            "/api/indicators/" + str(iid) + "/attributes",
            data={"name": key, "value": value},
        )
        res = res.get("data")
        if not res or "attribute_id" not in res[0]:
            return None

        return res[0]["attribute_id"]

    def createeventtype(self, name):
        if not name:
            raise ValueError("Failed to provide event type name.")

        return self.post("/api/event/types", data={"name": name})

    def gettypename(self, typeid):
        """Convert an indicator type ID in to a human-readable type name

        :param int typeid: ID to find

        :returns: String type name, or None if the ID isn't found
        """
        typeinfo = self.get("/api/indicator/types")
        if not typeinfo:
            _logger.debug("Failed to get indicator types")
            return None

        for t in typeinfo["data"]:
            if t["id"] == typeid:
                return t["name"]

        return None

    def get_indicator_type_by_name(self, type_name):
        """Convert an indicator type name to ID

        :param str type_name: Indicator type to query

        :returns: int type ID, or None if the type_name isn't found
        """
        typeinfo = self.get("/api/indicator/types", params={"name": type_name})

        if typeinfo.get("data"):
            return typeinfo.get("data", [])[0].get("id")
        else:
            return None

    def getstatusname(self, statusid):
        """Convert an indicator status ID in to a human-readable type name

        :param int statusid: ID to find

        :returns: String status name, or None if the ID isn't found
        """
        statusinfo = self.get("/api/indicator/statuses")
        if not statusinfo:
            _logger.debug("Failed to get indicator statuses")
            return None

        for s in statusinfo["data"]:
            if s["id"] == statusid:
                return s["name"]

        return None

    def getstatusidbyname(self, statusname):
        """Convert an indicator name to its numerical ID

        :param str statusname: Name to find

        :returns: Integer status ID, or None if the name isn't found
        """
        if not self.statusinfo:
            self.statusinfo = self.get("/api/indicator/statuses")
            if not self.statusinfo:
                _logger.debug("Failed to get indicator statuses")
                return None

        for s in self.statusinfo["data"]:
            if s["name"] == statusname:
                return s["id"]

        return None

    def geteventtypename(self, typeid):
        """Convert an event type ID to a human-readable name

        :param int typeid: ID to find

        :returns: String, or None if the ID isn't found
        """
        typeinfo = self.get("/api/event/types")
        if not typeinfo:
            _logger.debug("Failed to get event types")
            return None

        for t in typeinfo["data"]:
            if t["id"] == typeid:
                return t["name"]

        return None

    def bulkuploadindicators(
        self, indicators, source=None
    ):  # noqa - "source" overrides a global, unsafe to fix

        inds = []

        for i in indicators:
            i = i.to_dict()
            if source:
                i["sources"] = [{"name": source}]
            inds.append(i)

        res = self.post("/api/indicators/consume/new", data=inds)
        r = res.get("data")
        if not r:
            raise exceptions.UploadFailedError(res)

        return res

    def geteventtypeidbyname(self, name):
        """Convert a human-readable event type name to its numerical ID

        :param str name: Name of the event type to find.

        :returns: Integer ID, or None if the name isn't found
        """
        typeinfo = self.get("/api/event/types")
        if not typeinfo:
            _logger.debug("Failed to get event types")
            return None

        for t in typeinfo["data"]:
            if t["name"] == name:
                return t["id"]

        return None

    def getparseridbyname(self, name):
        """Convert a human-readable event type name to its numerical ID

        :param str name: Name of the event type to find.

        :returns: Integer ID, or None if the name isn't found
        """
        typeinfo = self.get("/api/attachments/types?is_parsable=Y")
        if not typeinfo:
            _logger.debug("Failed to get parser types")
            return None

        for t in typeinfo["data"]:
            if t["name"] == name:
                return t["id"]

        return None

    def getsigparseridbyname(self, name):
        """Convert a human-readable event type name to its numerical ID

        :param str name: Name of the event type to find.

        :returns: Integer ID, or None if the name isn't found
        """
        typeinfo = self.get("/api/signature/types")
        if not typeinfo:
            _logger.debug("Failed to get parser types")
            return None

        for t in typeinfo["data"]:
            if t["name"] == name:
                return t["id"]

        return None

    def import_text2(
        self, text, source, parser="Generic Text"
    ):  # noqa - "source" overrides a global, unsafe to fix
        """ Submit some text to be imported

        :param str text: Text to be submitted
        :param str source: Source name to file the import under

        :raises:
            :py:class:`~threatqsdk.exceptions.UploadFailedError` if the \
                upload fails and we don't get an upload ID back

        :returns: Result of ``/api/imports/ID/commit``
        """
        res = self.post(
            "/api/imports",
            data={
                "content_type_id": self.getparseridbyname(parser),
                "text": text,
            },
        )

        r = res.get("data")
        if not r or "id" not in r:
            raise exceptions.UploadFailedError(res)

        iid = r["id"]
        self.put(
            "/api/imports/%i" % iid,
            data={
                "delete_after_import": 0,
                "import_source": source,
                "indicator_global_status": 4,
            },
        )

        res = self.get(
            "/api/imports/%i/indicators" % iid,
        )

        r = res.get("data")
        if not r:
            raise exceptions.UploadFailedError(res)

        self.delete("/api/imports/%i" % iid)

        return r

    def import_text(
        self, text, source, parser="Generic Text", normalize="N"
    ):  # noqa - "source" overrides, unsafe fix
        """ Submit some text to be imported

        :param str text: Text to be submitted
        :param str source: Source name to file the import under

        :raises:
            :py:class:`~threatqsdk.exceptions.UploadFailedError` if the \
                upload fails and we don't get an upload ID back

        :returns: Result of ``/api/imports/ID/commit``
        """
        res = self.post(
            "/api/imports",
            data={
                "content_type_id": self.getparseridbyname(parser),
                "text": text,
                "normalize": normalize,
            },
        )

        r = res.get("data")
        if not r or "id" not in r:
            raise exceptions.UploadFailedError(res)

        iid = r["id"]
        self.put(
            "/api/imports/%i" % iid,
            data={
                "delete_after_import": 0,
                "import_source": source,
                "indicator_global_status": 4,
                "normalize": normalize,
            },
        )
        return self.get("/api/imports/%i/commit" % iid)

    def upload_file(
        self,
        filename,
        source,
        locked=False,
        stype="Spearphish Attachment",
        tags=[],
    ):  # noqa - "source"
        """ Submit a file to be imported

        :param str filename: Name of the file to upload
        :param str source: Source name to file the import under
        :param bool delete: False if ThreatQuotient should retain the file

        :raises:
            :py:class:`~threatqsdk.exceptions.UploadFailedError` if the \
                upload fails and we don't get an upload ID back

        :returns: Result of ``/api/imports/ID/commit``
        """
        fname = os.path.basename(filename)
        new_filename = "%i-%s" % (
            random.randint(1, 100000),
            fname.replace(".", ""),
        )

        with open(filename, "rb") as inf:
            res = self.post(
                "/api/attachments/upload",
                data={
                    "resumableIdentifier": new_filename,
                    "resumableRelativePath": fname,
                    "resumableTotalChunks": 1,
                    "resumableFilename": fname,
                },
                files={"file": ("blob", inf, "application/octet-stream")},
            )

        res = self.post(
            "/api/attachments",
            data=dict(
                name=fname, type=stype, malware_locked=locked, sources=[source]
            ),
        )
        r = res.get("data")
        if not r or "id" not in r:
            _logger.debug("id missing from /api/attachments response")
            raise exceptions.UploadFailedError(res)

        for t in tags:
            res = self.post(
                "/api/attachments/%i/tags" % r["id"], data={"name": t}
            )

        f = File(self)
        f.fid = r["id"]
        return f

    def import_file(
        self, filename, source, delete=False
    ):  # noqa - "source" overrides a global, unsafe to fix
        """ Submit a file to be imported

        :param str filename: Name of the file to upload
        :param str source: Source name to file the import under
        :param bool delete: False if ThreatQuotient should retain the file

        :raises:
            :py:class:`~threatqsdk.exceptions.UploadFailedError` if the \
                upload fails and we don't get an upload ID back

        :returns: Result of ``/api/imports/ID/commit``
        """
        fname = os.path.basename(filename)
        new_filename = "%i-%s" % (
            random.randint(1, 100000),
            fname.replace(".", ""),
        )

        with open(filename, "rb") as inf:
            res = self.post(
                "/api/imports",
                data={
                    "resumableIdentifier": new_filename,
                    "resumableRelativePath": fname,
                    "resumableTotalChunks": 1,
                    "resumableFilename": fname,
                    "content_type_id": self.getparseridbyname("Generic Text"),
                },
                files={"file": ("blob", inf, "application/octet-stream")},
            )

        r = res.get("data")
        if not r or "id" not in r:
            _logger.debug("id missing from /api/imports response")
            raise exceptions.UploadFailedError(res)

        iid = r["id"]
        self.put(
            "/api/imports/%i" % iid,
            data={
                "delete_after_import": delete,
                "import_source": source,
                "indicator_global_status": 4,
            },
        )
        return self.get("/api/imports/%i/commit" % iid)

    def bulkuploadsignatures(
        self, signatures, source=None
    ):  # noqa - "source" overrides a global, unsafe to fix
        """Bulk upload of signatures (BulkSignature objects)

        :param list signatures: List of BulkSignature objects
        :param str source: Source of all signatures

        :returns: dict response from API
        """
        signatures = [s.to_dict() for s in signatures]
        if source:
            for sig in signatures:
                sig["source"] = source
        # noinspection PyTypeChecker
        res = self.post("/api/signatures/consume", data=signatures)
        r = res.get("data")
        if not r:
            raise exceptions.UploadFailedError(res)
        return res

    def create_bulk_signatures_list(
        self, text, type_id=None, typename=None, statusname="Review"
    ):
        """Convert string of signatures text to a list of BulkSignature objects

        :param str text: Signatures text
        :param int type_id: Type ID (Optional, either type_id or typename must be set)
        :param str typename: Type name (Optional, either type_id or typename must be set)
        :param str statusname: Signature status to apply to all signatures

        :returns: list of BulkSignature objects
        """
        sigs_list = []
        if (not type_id) and (not typename):
            raise ValueError("type_id or typename must be specified")
        if typename:
            type_id = self.getsigparseridbyname(typename)
        endpoint = "/api/signatures/import"
        data = {"text": text, "type_id": type_id}
        result = self.post(endpoint, data).get("data", [])
        if not result:
            raise exceptions.UploadFailedError(result)

        for r in result:
            sig = BulkSignature(self)
            sig.set_name(r.get("name"))
            sig.set_value(r.get("value"))
            sig.set_status(statusname)
            sig.type_id = type_id
            sig.hash = r.get("hash")
            sig.attributes = r.get("attributes", [])

            sigs_list.append(sig)

        return sigs_list

    def list_feeds(self):
        """Retrieve list of Feeds from Incoming Feeds

        :returns: list of Feed objects
        """
        feeds = []
        resp = self.get("/api/connectors?limit=1000&with=category,tlp")
        data = resp.get("data", [])
        for d in data:
            f = Feed(self)
            f.from_dict(d)
            feeds.append(f)

        return feeds
