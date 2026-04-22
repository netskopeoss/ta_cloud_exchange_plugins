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

SMB File Share Plugin Constants file.
"""

MODULE_NAME = "EDM"
PLUGIN_NAME = "SMB File Share"
PLUGIN_VERSION = "1.0.0"
SAMPLE_DATA_RECORD_COUNT = 20
SAMPLE_CSV_FILE_NAME = "sample.txt"
SMB_FILE_SHARE_EDM_FIELDS = {
    "configuration": [
        {
            "label": "Server Hostname/IP",
            "key": "smb_server_ip",
            "type": "text",
            "default": "",
            "mandatory": True,
            "placeholder": "e.g. fileserver.example.com or 192.0.2.19",
            "description": (
                "IP address or Hostname of the SMB server from which "
                "the CSV file should be pulled."
            ),
        },
        {
            "label": "Port",
            "key": "smb_port",
            "type": "number",
            "default": 445,
            "mandatory": True,
            "placeholder": "e.g. 445",
            "description": "TCP port for SMB connection (default 445).",
        },
        {
            "label": "Username",
            "key": "smb_username",
            "type": "text",
            "default": "",
            "mandatory": True,
            "placeholder": "Username",
            "description": (
                "Username with read access to the shared directory."
            ),
        },
        {
            "label": "Password",
            "key": "smb_password",
            "type": "password",
            "default": "",
            "mandatory": True,
            "placeholder": "Password",
            "description": "Password for the provided username.",
        },
        {
            "label": "Share Directory Name",
            "key": "smb_shared_directory_name",
            "type": "text",
            "default": "",
            "mandatory": True,
            "placeholder": "e.g. dept_shares",
            "description": (
                "The SMB share name. E.g. If the full UNC path is "
                "'\\\\server\\share\\path\\file.csv', enter 'share'."
            ),
        },
        {
            "label": "CSV File Path",
            "key": "smb_filepath",
            "type": "text",
            "default": "",
            "mandatory": True,
            "placeholder": "e.g. folder\\data.csv",
            "description": (
                "Provide a CSV file name or path of the CSV file "
                "relative to Share Directory Name. "
                "E.g. If the full UNC path is "
                "'\\\\server\\share\\path\\file.csv', enter 'path\\file.csv'. "
                "Use backslashes (\\\\) only."
            ),
            "helperText": (
                "Only .csv/.txt files with max 25 columns are "
                "supported. Use backslashes only; do not enter full UNC path."
            ),
        },
        {
            "label": "Delimiter",
            "key": "delimiter",
            "type": "text",
            "default": ",",
            "mandatory": True,
            "placeholder": "e.g. , or | or ;",
            "description": (
                "Single character delimiter used in the CSV/TXT file "
                "(e.g. comma, pipe, semicolon)."
            ),
        },
        {
            "label": "Remove Quotes",
            "key": "remove_quotes",
            "type": "boolean",
            "default": False,
            "mandatory": False,
            "description": (
                "Enable this if your CSV encloses fields in double quotes, "
                "especially when values contain commas. Quoted fields will be "
                "parsed as single columns. Improper quote placement may cause "
                "rows to be skipped."
            ),
            "helperText": (
                "Example: “123 Main St, Apt 4B” stays in one column instead "
                "of splitting. Enable this if your CSV encloses fields in "
                "double quotes, especially when values contain commas."
            ),
        },
    ],
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
                "By default, stopwords are included during data sanitization "
                "for all the columns. To reflect the changes in sanitization "
                "for any given column, make sure that column is selected as "
                "'Name Column' and 'Proceed without sanitization' is unchecked"
                " in the next step."
            ),
            "helperText": (
                "Stopwords are common words (e.g., 'is', 'the', 'and') that "
                "are often removed to improve accuracy."
            ),
        },
    ],
    "sanity_results": [
        {
            "label": "Preview Files",
            "key": "sanity_preview",
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
