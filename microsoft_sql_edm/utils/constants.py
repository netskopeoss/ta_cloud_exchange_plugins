"""Microsoft SQL EDM Plugin Constants file."""

SAMPLE_CSV_ROW_COUNT = 20
CONNECTION_TIMEOUT = 30
BATCH_SIZE = 100000
SQL_MODIFICATION_KEYWORDS = [
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
PLUGIN_NAME = "Microsoft SQL EDM"
MODULE_NAME = "EDM"
PLUGIN_VERSION = "1.0.0"
MICROSOFT_SQL_EDM_FIELDS = {
    "sanity_inputs": [
        {
            "label": "Sanitization Paramters",
            "key": "sanitization_input",
            "type": "sanitization_input",
            "default": {},
            "mandatory": False,
            "description": "Parameters required for sanitization and EDM hashing.",
        },
        {
            "label": "Remove stopwords",
            "key": "exclude_stopwords",
            "type": "boolean",
            "default": False,
            "mandatory": False,
            "description": "By default, stopwords are included during data sanitization for all the columns. To reflect the changes in sanitization for any given column, make sure that column is selected as 'Name Column' and 'Proceed without sanitization' is unchecked in the next step.",
            "helperText": "Stopwords are common words (e.g., 'is', 'the', 'and') that are often removed to improve accuracy.",
        },
    ],
    "sanity_results": [
        {
            "label": "Preview Files",
            "key": "sanitization_preview",
            "type": "sanitization_preview",
            "default": "",
            "mandatory": False,
            "description": "Preview options for viewing sanitized results. This provides a way to see the data before further processing.",
        },
        {
            "label": "Proceed without sanitization",
            "key": "is_unsanitized_data",
            "type": "boolean",
            "default": True,
            "mandatory": True,
        },
    ],
}
