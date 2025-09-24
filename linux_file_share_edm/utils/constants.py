"""Linux File Share EDM plugin constants file."""

PLUGIN_NAME = "Linux File Share EDM"
PLUGIN_VERSION = "1.0.0"
MODULE_NAME = "EDM"
SAMPLE_DATA_RECORD_COUNT = 20
LINUX_FILE_SHARE_FIELDS = {
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
}