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

OracleDB EDM Plugin Constants file.
"""

SAMPLE_CSV_ROW_COUNT = 20
MODULE_NAME = "EDM"
PLUGIN_NAME = "OracleDB"
PLUGIN_VERSION = "1.1.0"
BATCH_SIZE = 100000
SAMPLE_CSV_FILE_NAME = "sample.csv"
SQL_KEYWORDS_TO_CHECK = [
    "create",
    "drop",
    "alter",
    "truncate",
    "comment",
    "rename",
    "insert",
    "update",
    "delete",
    "lock",
    "call",
    "explain plan",
    "grant",
    "revoke",
    "commit",
    "rollback",
    "savepoint",
    "transaction",
    "set transaction",
    "constraint",
    "set constraint",
    "set",
]

ORACLE_EDM_FIELDS = {
    "sanity_inputs": [
        {
            "label": "Sanitization Parameters",
            "key": "sanitization_input",
            "type": "sanitization_input",
            "default": {},
            "mandatory": False,
            "description": (
                "Parameters required for sanitization and EDM hashing."
            ),
        },
        {
            "label": "Remove Stopwords",
            "key": "exclude_stopwords",
            "type": "boolean",
            "default": False,
            "mandatory": False,
            "description": (
                "By default, stopwords are included during data "
                "sanitization for all the columns. "
                "To reflect the changes in sanitization for any given column, "
                "make sure that column "
                "is selected as 'Name Column' and 'Proceed without "
                "sanitization' is unchecked in the next step."
            ),
            "helperText": (
                "Stopwords are common words (e.g., 'is', 'the', 'and') "
                "that are often removed to improve accuracy."
            ),
        },
    ],
    "sanity_results": [
        {
            "label": "Preview Files",
            "key": "sanitization_preview",
            "type": "sanitization_preview",
            "default": "",
            "mandatory": False,
            "description": (
                "Preview options for viewing sanitized results. "
                "This provides a way to see the data before "
                "further processing. "
                "It includes both 'good' and 'bad' files, "
                "indicating data that passed and data that "
                "didn't meet the sanitization criteria."
            ),
            "readonly": True,
        },
        {
            "label": "Proceed Without Sanitization",
            "key": "is_unsanitized_data",
            "type": "boolean",
            "default": True,
            "mandatory": True,
        },
    ],
}
