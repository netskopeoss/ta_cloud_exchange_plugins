"""Microsoft File Share plugin constants file."""

PLUGIN_NAME = "Microsoft File Share CFC"
MODULE_NAME = "CFC"
PLUGIN_VERSION = "1.0.0"
SUPPORTED_IMAGE_FILE_EXTENSIONS = [".bmp", ".dib", ".jpeg", ".jpg", ".jpe", ".jp2", ".png", ".webp", ".avif", ".pbm",
                                   ".pgm", ".ppm", ".pxm", ".pnm", ".pfm", ".sr", ".ras",  ".tiff", ".tif", ".exr",
                                   ".hdr", ".pic", ".zip", ".tgz"]
ALLOWED_FILE_COUNT = 10000
ALLOWED_FILE_SIZE = (80000 * 1024 * 1024)
MICROSOFT_FILE_SHARE_FIELDS = {
    "SMB": {
        "configuration_parameters": [
            {
                "label": "Server IP/Hostname",
                "key": "smb_server_ip",
                "type": "text",
                "default": "",
                "mandatory": True,
                "placeholder": "e.g. 192.0.2.19/www.example.com",
                "description": (
                    "IP address or Hostname of the Windows machine from which "
                    "the files are to be pulled."
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
                    "to shared directories."
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
        ],
        "directory_configuration": [
            {
                "label": "Shared Directory",
                "key": "directory_inputs",
                "type": "directory_inputs",
                "mandatory": True,
                "placeholder": "Shared directory name",
                "description": ("Name of the Windows shared directory. Ensure that this directory name is present "
                                "in the Network Path of the shared directory."),
                "fields": [
                    {
                        "label": "Directory Paths",
                        "key": "directory_paths",
                        "type": "directory_paths",
                        "mandatory": True,
                        "description": "Path of the Windows directories from which the files are to be pulled.",
                        "fields": [
                            {
                                "label": "Directory Path",
                                "key": "directory_path",
                                "type": "text",
                                "default": "",
                                "mandatory": True,
                                "placeholder": "e.g. \\Medical Data\\Xrays",
                                "description": ("Path of the Windows directory from which the files are to be pulled. "
                                                "This path must be relative to the shared directory."),
                            },
                            {
                                "label": "Filename Filter",
                                "key": "filename_filter",
                                "type": "text",
                                "default": "",
                                "mandatory": False,
                                "placeholder": "e.g. xrays_.*.jpg",
                                "description": ("Regular expression that filters the files to be "
                                                "pulled based on their filenames. Ensure that the "
                                                "filter is a valid regular expression. If left empty, "
                                                "all files from the directory will be retrieved. "
                                                "Note that this filter is applied only to files "
                                                "directly stored in the specified directory and does "
                                                "not include files from sub-directories. "),
                            }
                        ]
                    }
                ]
            }
        ],
        "file_results": [
            {
                "label": "Preview File Details",
                "key": "file_count_result",
                "type": "file_count_result",
                "default": {},
                "mandatory": False,
                "description": "Preview file results."
            }
        ]
    },
    "SFTP": {
        "configuration_parameters": [
            {
                "label": "Server IP/Hostname",
                "key": "sftp_server_ip",
                "type": "text",
                "default": "",
                "mandatory": True,
                "placeholder": "e.g. 192.0.2.19/www.example.com",
                "description": (
                    "IP address or Hostname of the Windows machine "
                    "from which the files are to be pulled."
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
                    "TCP port number to connect to "
                    "the OpenSSH service on the Windows machine."
                ),
            },
        ],
        "directory_configuration": [
            {
                "label": "Directory Paths",
                "key": "directory_paths",
                "type": "directory_paths",
                "mandatory": True,
                "description": "Path of the Windows directories from which the files are to be pulled.",
                "fields": [
                    {
                        "label": "Directory Path",
                        "key": "directory_path",
                        "type": "text",
                        "default": "",
                        "mandatory": True,
                        "placeholder": "e.g. C:\\Users\\Administrator\\Hospital Data\\Medical Data\\Xrays",
                        "description": "Path of the Windows directory from which the files are to be pulled.",
                    },
                    {
                        "label": "Filename Filter",
                        "key": "filename_filter",
                        "type": "text",
                        "default": "",
                        "mandatory": False,
                        "placeholder": "e.g. xrays_.*.jpg",
                        "description": ("Regular expression that filters the files to be "
                                        "pulled based on their filenames. Ensure that the "
                                        "filter is a valid regular expression. If left empty, "
                                        "all files from the directory will be retrieved. "
                                        "Note that this filter is applied only to files "
                                        "directly stored in the specified directory and does "
                                        "not include files from sub-directories. "),
                    }
                ]
            }
        ],
        "file_results": [
            {
                "label": "Preview File Details",
                "key": "file_count_result",
                "type": "file_count_result",
                "default": {},
                "mandatory": False,
                "description": "Preview file results."
            }
        ]
    }
}
