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

from logging import getLogger
import os
import random

from . import exceptions
from .source import make_source_list
from .tqobject import ThreatQuotientObject

_logger = getLogger(__name__)


class File(ThreatQuotientObject):
    """ Represents an Adversary in the ThreatQ system """

    def __init__(self, tq):
        self.tq = tq
        self.path = None
        self.name = None
        self.fid = None
        self.ftype = None
        self.locked = False
        self.tags = []
        self.title = None

    @staticmethod
    def _get_base_endpoint_name():
        return 'attachments'

    def _id(self):
        return self.fid

    def _set_id(self, value):
        self.fid = value

    def fill_from_api_response(self, api_response):
        self.fid = api_response['id']
        self.name = api_response['name']
        self.description = None

    def _to_dict(self):
        raise NotImplementedError("File uploads don't serialize well")

    def _file_url(self, fid):
        """ Get a link to the file suitable for presentation to an
        end user

        :param fid: File ID
        :type fid: int
        """
        base = self.tq.threatq_host + '/files/'
        return base + str(fid) + '/details'

    def parse_and_import(self, source, status='Review', parser='Generic Text', normalize=True, delete=False):
        """ Parse the file and import the indicators using a parser

        :param str source: Source to use for each Indicator
        :param str status: Indicator status
        :param str parser: What parser to use
        :param bool normalize: Normalize URL indicators
        :param bool delete: Delete the file/attachment after import

        :returns: Import message
        """

        parser_id = self.tq.getparseridbyname(parser)
        status_id = self.tq.getstatusidbyname(status)

        if not parser_id:
            raise ValueError('Invalid parser')

        if not status_id:
            raise ValueError('{} is not a valid status'.format(status))

        res = self.tq.post(
            '/api/imports',
            data={
                'attachment_id': self.fid,
                'normalize': normalize,
                'content_type_id': parser_id
            })

        r = res.get('data')
        if not r or 'id' not in r:
            raise exceptions.UploadFailedError(res)

        iid = r['id']
        self.tq.put(
            '/api/imports/%i' % iid,
            data={
                'delete_after_import': delete,
                'import_source': source,
                'indicator_global_status': status_id
            })
        return self.tq.get('/api/imports/%i/commit' % iid)

    def upload(self, sources=None):
        """ Upload ourself to threatq """
        # Backwards compatible with < v1.4
        if self.path is None:
            self.path = self.name

        if self.name is None:
            raise ValueError("Cannot upload without a file name")

        if self.ftype is None:
            raise ValueError("Cannot upload without a file type")

        data = {}
        sources = make_source_list(sources)
        if sources is not None and len(sources) > 0:
            data['sources'] = [x.to_dict() for x in sources]

        fname = os.path.basename(self.name)
        new_filename = "%i-%s" % (
            random.randint(1, 100000),
            fname.replace('.', ''))

        with open(self.path, 'rb') as inf:
            res = self.tq.post(
                '/api/attachments/upload',
                data={
                    'resumableIdentifier': new_filename,
                    'resumableRelativePath': fname,
                    'resumableTotalChunks': 1,
                    'resumableFilename': fname,
                },
                files={
                    'file': ('blob', inf, 'application/octet-stream')
                })

        data['name'] = fname
        if self.title:
            data['title'] = self.title
        data['type'] = self.ftype
        data['malware_locked'] = self.locked

        res = self.tq.post('/api/attachments', data=data)

        r = res.get('data')
        if not r or 'id' not in r:
            _logger.debug('id missing from /api/attachments response')
            raise exceptions.UploadFailedError(res)

        for t in self.tags:
            res = self.tq.post('/api/attachments/%i/tags' %
                               r['id'], data={'name': t})

        self.fid = r['id']

        return self

    def get_related_indicators(self):
        """ Get the indicators related to this Adversary

        .. deprecated:: 1.01
            Use :py:meth:`threatqsdk.tqobject.get_related_objects` instead
        """
        # imported here to prevent circular deps
        from threatqsdk.indicator import Indicator
        return self.get_related_objects(Indicator)

    def url(self):
        """ Get a link to the file suitable for presentation to an
        end user

        :raises: :py:class:`~threatqsdk.exceptions.NotCreatedError` if
                the indicator has yet to be created
        """
        if not self.fid:
            raise exceptions.NotCreatedError(object=self)

        return self._file_url(self.fid)


def get_file(tq, fid):
    a = File(tq)
    a.fid = fid

    basic_data = tq.get(a._get_api_endpoint())['data']
    try:
        description = tq.get(a._get_api_endpoint() + '/description')['data']
    except Exception:
        description = ''

    a.name = basic_data['name']
    a.description = description

    return a
