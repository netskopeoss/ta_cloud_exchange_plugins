"""Microsoft File Share EDM Plugin Constants file."""

MODULE_NAME = "EDM"
PLUGIN_NAME = "Microsoft File Share EDM"
PLUGIN_VERSION = "1.0.0"
SAMPLE_DATA_RECORD_COUNT = 20
MICROSOFT_FILE_SHARE_EDM_FIELDS = {
    "SMB": {
        "configuration": [
            {
                "label": "Server IP/Hostname",
                "key": "smb_server_ip",
                "type": "text",
                "default": "",
                "mandatory": True,
                "placeholder": "e.g. 192.0.2.19/www.example.com",
                "description": (
                    "IP address or Hostname of the Windows machine from which "
                    "the CSV file should be pulled."
                ),
            },
            {
                "label": "Machine Name",
                "key": "smb_machine_name",
                "type": "text",
                "default": "",
                "mandatory": True,
                "placeholder": "e.g. WIN-131CUS090LI",
                "description": "NetBIOS machine name of the Windows server.",
            },
            {
                "label": "Username",
                "key": "smb_username",
                "type": "text",
                "default": "",
                "mandatory": True,
                "placeholder": "Username",
                "description": (
                    "Username of the Windows machine which has read access "
                    "to shared directory."
                ),
            },
            {
                "label": "Password",
                "key": "smb_password",
                "type": "password",
                "default": "",
                "mandatory": True,
                "placeholder": "Password",
                "description": "Password for the provided Windows username.",
            },
            {
                "label": "Shared Directory Name",
                "key": "smb_shared_directory_name",
                "type": "text",
                "default": "",
                "mandatory": True,
                "placeholder": "e.g. file_share_edm",
                "description": "Name of the Windows shared directory.",
            },
            {
                "label": "CSV File Path",
                "key": "smb_filepath",
                "type": "text",
                "default": "",
                "mandatory": True,
                "placeholder": "e.g. files-data\\netskope-data\\data.csv",
                "description": (
                    "Path of the CSV file to be pulled from the configured Windows machine. "
                    "This path must be relative to the shared directory."
                ),
                "helperText": "Note: Only .csv file with a maximum of 25 columns are supported."
            },
        ],
        "sanity_inputs": [
            {
                "label": "Sanitization Parameters",
                "key": "sanitization_input",
                "type": "sanitization_input",
                "default": {},
                "mandatory": False,
                "description": "Parameters required for sanitization and EDM hashing."
            },
            {
                "label": "Remove stopwords",
                "key": "exclude_stopwords",
                "type": "boolean",
                "default": False,
                "mandatory": False,
                "description": "By default, stopwords are included during data sanitization for all the columns. To reflect the changes in sanitization for any given column, make sure that column is selected as 'Name Column' and 'Proceed without sanitization' is unchecked in the next step.",
                "helperText": "Stopwords are common words (e.g., 'is', 'the', 'and') that are often removed to improve accuracy."
            }
        ],
        "sanity_results": [
            {
                "label": "Preview Files",
                "key": "sanity_preview",
                "type": "sanitization_preview",
                "default": "",
                "mandatory": False,
                "description": "Preview options for viewing sanitized results. This provides a way to see the data before further processing. It includes both 'good' and 'bad' files, indicating data that passed and data that didn't meet the sanitization criteria.",
                "readonly": True
            },
            {
                "label": "Proceed without sanitization",
                "key": "is_unsanitized_data",
                "type": "boolean",
                "default": True,
                "mandatory": True
            }
        ]
    },
    "SFTP": {
        "configuration": [
            {
                "label": "Server IP/Hostname",
                "key": "sftp_server_ip",
                "type": "text",
                "default": "",
                "mandatory": True,
                "placeholder": "e.g. 192.0.2.19/www.example.com",
                "description": (
                    "IP address or Hostname of the Windows machine "
                    "from which the CSV file should be pulled."
                ),
            },
            {
                "label": "Username",
                "key": "sftp_username",
                "type": "text",
                "default": "",
                "mandatory": True,
                "placeholder": "Username",
                "description": (
                    "Username of the Windows machine that is configured "
                    "to use OpenSSH service on the machine."
                ),
            },
            {
                "label": "Password",
                "key": "sftp_password",
                "type": "password",
                "default": "",
                "mandatory": True,
                "placeholder": "Password",
                "description": "Password for the provided Windows username.",
            },
            {
                "label": "Port",
                "key": "sftp_port",
                "type": "number",
                "default": 22,
                "mandatory": True,
                "placeholder": "e.g. 22",
                "description": (
                    "TCP port number to use for connecting to "
                    "the OpenSSH service on the Windows machine."
                ),
            },
            {
                "label": "CSV File Path",
                "key": "sftp_filepath",
                "type": "text",
                "default": "",
                "mandatory": True,
                "placeholder": "e.g. C:\\Users\\Administrator\\files-data\\netskope-data\\data.csv",
                "description": "Path of the CSV file to be pulled from the configured Windows machine.",
                "helperText": "Note: Only .csv file with a maximum of 25 columns are supported."
            },
        ],
        "sanity_inputs": [
            {
                "label": "Sanitization Parameters",
                "key": "sanitization_input",
                "type": "sanitization_input",
                "default": {},
                "mandatory": False,
                "description": "Parameters required for sanitization and EDM hashing."
            },
            {
                "label": "Remove stopwords",
                "key": "exclude_stopwords",
                "type": "boolean",
                "default": False,
                "mandatory": False,
                "description": "By default, stopwords are included during data sanitization for all the columns. To reflect the changes in sanitization for any given column, make sure that column is selected as 'Name Column' and 'Proceed without sanitization' is unchecked in the next step.",
                "helperText": "Stopwords are common words (e.g., 'is', 'the', 'and') that are often removed to improve accuracy."
            }
        ],
        "sanity_results": [
            {
                "label": "Preview Files",
                "key": "sanity_preview",
                "type": "sanitization_preview",
                "default": "",
                "mandatory": False,
                "description": "Preview options for viewing sanitized results. This provides a way to see the data before further processing. It includes both 'good' and 'bad' files, indicating data that passed and data that didn't meet the sanitization criteria.",
                "readonly": True
            },
            {
                "label": "Proceed without sanitization",
                "key": "is_unsanitized_data",
                "type": "boolean",
                "default": True,
                "mandatory": True
            }
        ]
    },
}
