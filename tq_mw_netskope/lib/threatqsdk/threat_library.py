# -*- coding: utf-8 -*-
###########################################################################################################
# ThreatQuotient Proprietary and Confidential
# Copyright (c)2020 ThreatQuotient, Inc. All rights reserved.
#
# NOTICE: All information contained herein, is, and remains the property of ThreatQuotient, Inc.
# The intellectual and technical concepts contained herein are proprietary to ThreatQuotient, Inc.
# and its suppliers and may be covered by U.S. and Foreign Patents, patents in process, and are
# protected by trade secret or copyright law.
#
# Dissemination of this information or reproduction of this material is strictly forbidden unless prior
# written permission is obtained from ThreatQuotient, Inc.
###########################################################################################################

import sys
import json
import requests
import logging

from copy import copy, deepcopy

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

string_types = (str,)
if sys.version_info < (3,):
    string_types += (unicode,)


class ThreatLibrary(object):
    """
    Executes a search using ThreatQ's Threat Library endpoints
    """

    default_query = {
        "name": None,
        "json": {
            "ui_query": {
                "columns": {},
                "criteria": {},
                "filters": {},
                "objects": {
                    "current": "indicators",
                    "selected": []
                },
                "filter_sets": [
                    {
                        "id": 0,
                        "operator": "+or",
                        "expanded": True
                    }
                ]
            },
            "api_query": {
                "criteria": {},
                "filters": {}
            }
        }
    }

    def __init__(self, tq, fields=None):
        """
        Instantiates a ThreatLibrarySearch object

        Parameters:
            - tq (Threatq): A ThreatQ connection object
            - object_type (str): The object type you want to execute the query on
            - fields (list): List of fields to return from the Threat Library
            - load_objects (bool): Whether or not to dynamically load in objects, types, and statuses
        """

        self.tq = tq
        self.saved_search = {}
        self.total = 0
        self.fields = fields or []
        self.date_injected = False

        # Object data
        self.object_list = []
        self.object_types = {}
        self.object_statuses = {}

        # Load object data from the ThreatQ instance
        self._load_object_list()

    def create_search_hash(self, mentions=None, json_data=None):
        """
        DEPRECATED: This is only here for backwards compatible-ness

        Parameters:
            - mentions (str): Comma-separated list of values to search for keywords on
            - json_data (dict): The exact JSON data to be sent to the API to create a search
        """

        return self.create_search(keywords=mentions, api_query=json_data)

    def create_search(self, name=None, keywords=None, api_query=None):
        """
        Creates a Threat Library search

        Parameters:
            - name (str): A name for the search. If none provided, it will not be "saved" officially
            - keywords (list): A list of keywords to search for
            - api_query (dict): A pre-generated API query to use
        """

        if not keywords and not api_query:
            raise ValueError('You must include either a "keywords" or "api_query" parameter')

        if isinstance(keywords, string_types):
            keywords = keywords.split(',')

        body = copy(self.default_query)
        body['name'] = name

        if keywords:
            # Build criteria
            ui_items = []
            api_items = []
            for item in keywords:
                api_items.append({"mentions": item.strip()})
                ui_items.append({
                    'key': 'mentions',
                    'value': item.strip(),
                    'set_id': 0
                })

            # Set UI query
            body['json']['ui_query']['criteria'] = {
                'matchType': {'0': '+or'},
                'items': ui_items
            }

            # Set API query
            body['json']['api_query']['criteria'] = {"+or": api_items}
        elif api_query:
            body['json']['api_query'] = api_query

        queries = self.tq.post('api/search/query', data=body)
        if queries and queries.get('data'):
            self.saved_search = queries['data']

        return self

    def get_saved_search(self, name):
        """
        Gets the saved search data by name

        Parameters:
            - name (str): The name of the saved search to get
        """

        queries = self.tq.get('api/search/query')
        if not queries or 'data' not in queries:
            raise ValueError('ThreatQ saved search query did not return any results')

        results = [x for x in queries['data'] if x['name'] == name]
        if not results:
            raise ValueError('No saved searches match the name provided')

        self.saved_search = results[0]

        # Load the search query from the response
        search = self.saved_search.get('json')
        if not search:
            raise ValueError("Search did not contain any criteria!")

        # If the query is stringified, load it as a JSON object
        if isinstance(search, string_types):
            search = json.loads(search)

        # Set the query to the true JSON object
        self.saved_search['json'] = search
        return self

    def execute(self, object_type, custom_query={}, page_limit=1000,
                page_offset=0, max_results=None, yield_batches=False, fields=[]):
        """
        Executes a query against the Threat Library and passes each batch to the caller to handle

        Parameters:
            - object_type (str): The object type within the ThreatQ system
            - query (dict): The query to execute. Will override the saved search
            - limit (int): The max amount of results per-page
            - max_result (int): The max amount of results to return (this is a hard stop)
        """

        search = {}
        self.total = 0  # Reset the total count

        # Make sure a saved search exists or they're overriding it with a custom query
        if not custom_query and not self.saved_search:
            raise ValueError('You cannot execute a search without a JSON query')

        # Parse the JSON payload if using a saved search
        if custom_query:
            search = custom_query.get('api_query', custom_query)
        else:
            search = self.saved_search['json']

        # Match the passed object type to one from ThreatQ
        api_name = self._match_api_name(object_type)
        if not api_name:
            raise ValueError("Object type [{}] does not exist in ThreatQ!".format(object_type))

        # Sanitize the payload by stripping out criteria
        # on objects that don't have certain properties
        payload = self.sanitize_payload(api_name, search)

        # If there is already an API query or manual query, use that
        if 'api_query' in payload or custom_query:
            payload = payload.get('api_query', payload)

        # Add in the fields
        payload['fields'] = fields or self.fields
        logger.debug('Executing [{}] Query: {}'.format(api_name, json.dumps(payload)))

        # paginate through results
        total = -1
        offset = page_offset
        while total == -1 or (offset < total and offset < max_results):
            params = {'limit': page_limit, 'offset': offset}
            res = {}

            try:
                res = self.tq.post('api/{}/query'.format(api_name), params=params, data=payload)
            except requests.exceptions.ConnectionError:
                logger.warning("BadStatusLine Error. Continuing...")
                continue  # Retry request

            if not res or 'data' not in res:
                raise ValueError('ThreatQ Threat Library Search for {} returned no data.'.format(api_name))

            # Store values for pagination
            offset += len(res['data'])

            # Set the total results
            self.total = res['total']

            # Handle "first page" stuff
            if total == -1:
                total = res['total']
                logger.debug('Threat Library search found {} total results'.format(total))
                max_results = total if not max_results else max_results

            ret = [item for item in res['data'] if item]
            if yield_batches:
                yield ret
            else:
                for i in ret:
                    yield i

    def sanitize_payload(self, object_type, payload):
        """
        Remove any unused payload filters, per-object type

        Parameters:
            - object_type (str): The object code for the payload
            - payload (dict): The search payload
        """

        payload = deepcopy(payload)

        # Remove typename
        if object_type not in self.object_types.keys():
            Utils.strip_keys(payload, keys=['types', 'type_name'])
        else:
            # Make sure we are only querying for types that apply to the object
            values = Utils.get_key_values(payload, 'type_name')
            for val in values:
                if val not in self.object_types.get(object_type, []):
                    Utils.strip_key_value(payload, 'type_name', val)

        # Remove status name
        if object_type not in self.object_statuses.keys():
            Utils.strip_keys(payload, keys=['statuses', 'status_name'])
        else:
            # Make sure we are only querying for types that apply to the object
            values = Utils.get_key_values(payload, 'status_name')
            for val in values:
                if val not in self.object_statuses.get(object_type):
                    Utils.strip_key_value(payload, 'status_name', val)

        # Remove score
        if object_type not in ['indicators']:
            Utils.strip_keys(payload, keys=['score'])

        # Remove empty items
        rem = None
        while rem is None or rem != 0:
            rem = Utils.strip_empty(payload, ignore=['filters', 'criteria'])

        return payload

    def inject_date(self, start_date, end_date="NOW", date_type='created_at'):
        """
        Injects a date into the payload

        Parameters:
            - start_date (str): A string representation of a start date, or a laravel relative date
            - end_date (str): A string representation of an end date, or a laravel relative date
            - date_type (str): The date type to inject
        """

        # Load the search JSON
        search_json = self.saved_search['json']

        # List of possible dates in search
        date_types = ['created_at', 'updated_at', 'touched_at']

        if 'api_query' not in search_json:
            raise ValueError("Cannot inject date into search without an API query")

        # Detect the 'key' to inject into. Either criteria or filters. Default to criteria
        field = 'criteria'
        if search_json['api_query'].get('filters'):
            field = 'filters'

        # Copy the filters and make sure that it has an "+and" list
        filters = copy(search_json['api_query'][field])
        if not filters:
            filters = {}
        if '+and' not in filters:
            filters['+and'] = []

        # Remove other dates from the "+and" filter list
        for f in range(len(filters['+and'])):
            for k, v in filters['+and'][f].items():
                if k in date_types:
                    del filters['+and'][f][k]

        # Inject new date
        filters['+and'].append({
            date_type: {
                "+gt": start_date,
                "+lt": end_date
            }
        })

        # Set the new JSON with injected date
        self.saved_search['json']['api_query'][field] = filters
        self.date_injected = True

    def _match_api_name(self, value):
        """
        Matches an input to an API name
        """

        if not self.object_list:
            raise ValueError("No ThreatQ object data loaded!")

        c_val = Utils.standardize_value(value)

        for obj_data in self.object_list:
            if (
                Utils.standardize_value(obj_data['collection']) == c_val or
                Utils.standardize_value(obj_data['display_name']) == c_val or
                Utils.standardize_value(obj_data['display_name_plural']) == c_val
            ):
                return obj_data['collection']

    def _load_object_list(self):
        """
        Loads in objects and types from ThreatQ
        """

        # Get objects
        ignore = ['objectlinks', 'investigations']
        data = self.tq.get('/api/objects').get('data', [])
        if not data:
            raise ValueError("Failed to get objects from ThreatQ!")

        # Get list of objects and filter out ones we want to ignore
        self.object_list = [val for val in data if val['collection'] not in ignore]

        # Fill out object data
        for obj in self.object_list:
            api_name = obj['collection']

            if 'types' in obj and len(obj['types']) > 0:
                if api_name not in self.object_types:
                    self.object_types[api_name] = []
                for type_data in obj['types']:
                    if type_data['name'] not in self.object_types[api_name]:
                        self.object_types[api_name].append(type_data['name'])

            if 'statuses' in obj and len(obj['statuses']) > 0:
                if api_name not in self.object_statuses:
                    self.object_statuses[api_name] = []
                for status_data in obj['statuses']:
                    if status_data['name'] not in self.object_statuses[api_name]:
                        self.object_statuses[api_name].append(status_data['name'])


class Utils:

    @staticmethod
    def strip_keys(input_data, keys=[], key_ends=[], skip=[]):
        """
        Removes items from input
        """

        if isinstance(input_data, dict):
            for key in list(input_data.keys()):
                if key in keys and key not in skip:
                    del input_data[key]
                elif any(key.endswith(k) for k in key_ends) and key not in skip:
                    del input_data[key]
                elif isinstance(input_data[key], list) or isinstance(input_data[key], dict):
                    Utils.strip_keys(input_data[key], keys=keys, key_ends=key_ends, skip=skip)
        elif isinstance(input_data, list):
            for i in reversed(range(len(input_data))):
                Utils.strip_keys(input_data[i], keys=keys, key_ends=key_ends, skip=skip)
        else:
            pass

    @staticmethod
    def strip_empty(input_data, ignore=[]):
        """
        Removes items from input
        """

        total = 0

        if isinstance(input_data, dict):
            for key in list(input_data.keys()):
                if isinstance(input_data[key], list) or isinstance(input_data[key], dict):
                    if key not in ignore and not input_data[key]:
                        del input_data[key]
                        total += 1
                    else:
                        total += Utils.strip_empty(input_data[key], ignore=ignore)
        elif isinstance(input_data, list):
            for i in reversed(range(len(input_data))):
                if not input_data[i]:
                    del input_data[i]
                    total += 1
                else:
                    total += Utils.strip_empty(input_data[i], ignore=ignore)
        else:
            pass

        return total

    @staticmethod
    def get_key_values(input_data, key):
        """
        Removes items from input
        """

        values = []

        if isinstance(input_data, dict):
            for k in list(input_data.keys()):
                if isinstance(input_data[k], list) or isinstance(input_data[k], dict):
                    values.extend(Utils.get_key_values(input_data[k], key))
                elif key == k:
                    values.append(input_data[k])
        elif isinstance(input_data, list):
            for i in reversed(range(len(input_data))):
                values.extend(Utils.get_key_values(input_data[i], key))
        else:
            pass

        return values

    @staticmethod
    def strip_key_value(input_data, key, value):
        """
        Removes items from input
        """

        if isinstance(input_data, dict):
            for k in list(input_data.keys()):
                if isinstance(input_data[k], list) or isinstance(input_data[k], dict):
                    Utils.strip_key_value(input_data[k], key, value)
                elif key == k and input_data[k] == value:
                    del input_data[k]
        elif isinstance(input_data, list):
            for i in reversed(range(len(input_data))):
                Utils.strip_key_value(input_data[i], key, value)
        else:
            pass

    @staticmethod
    def standardize_value(value):
        """
        Strips characters out of a string to standardize it
        """

        if not value:
            return value

        value = value.replace('_', '')
        value = value.replace(' ', '')
        value = value.replace('-', '')
        value = value.strip()
        return value.lower()
