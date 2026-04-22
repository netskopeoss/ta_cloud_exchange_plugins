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

SMB File Share CFC Plugin Constants file.
"""

MODULE_NAME = "CFC"
PLUGIN_NAME = "SMB File Share"
PLUGIN_VERSION = "1.0.0"
SUPPORTED_IMAGE_FILE_EXTENSIONS = [
    ".bmp", ".dib", ".jpeg", ".jpg", ".jpe",
    ".jp2", ".png", ".webp", ".avif", ".pbm",
    ".pgm", ".ppm", ".pxm", ".pnm", ".pfm",
    ".sr", ".ras", ".tiff", ".tif", ".exr",
    ".hdr", ".pic", ".zip", ".tgz"
]
ALLOWED_FILE_COUNT = 10000
ALLOWED_FILE_SIZE = 80 * 1024 * 1024 * 1024
SMB_FILE_SHARE_CFC_FIELDS = {
    "configuration_parameters": [
        {
            "label": "Server Hostname/IP",
            "key": "smb_server_ip",
            "type": "text",
            "default": "",
            "mandatory": True,
            "placeholder": (
                "e.g. fileserver.example.com or 192.0.2.19"
            ),
            "description": (
                "Hostname or IP address of the SMB server from which "
                "the files are to be pulled."
            ),
        },
        {
            "label": "Port",
            "key": "smb_port",
            "type": "number",
            "default": 445,
            "mandatory": True,
            "placeholder": "e.g. 445",
            "description": (
                "TCP port for SMB connection (default 445)."
            ),
        },
        {
            "label": "Username",
            "key": "smb_username",
            "type": "text",
            "default": "",
            "mandatory": True,
            "placeholder": "Username",
            "description": (
                "Username of the remote machine which has read access "
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
            "description": (
                "Password for the provided username."
            ),
        },
    ],
    "directory_configuration": [
        {
            "label": "Shared Directory",
            "key": "directory_inputs",
            "type": "directory_inputs",
            "mandatory": True,
            "placeholder": "Shared directory name",
            "description": (
                "Name of the shared directory. "
                "Ensure that this directory name is present "
                "in the Network Path of the shared directory."
            ),
            "fields": [
                {
                    "label": "Directory Paths",
                    "key": "directory_paths",
                    "type": "directory_paths",
                    "mandatory": True,
                    "description": (
                        "Path of the directories from "
                        "which the files are to be pulled."
                    ),
                    "fields": [
                        {
                            "label": "Directory Path",
                            "key": "directory_path",
                            "type": "text",
                            "default": "",
                            "mandatory": True,
                            "placeholder": "e.g. \\Medical Data\\Xrays",
                            "description": (
                                "Path of the directory from which the files "
                                "are to be pulled. "
                                "This path must be relative to the "
                                "shared directory."
                            ),
                        },
                        {
                            "label": "Filename Filter",
                            "key": "filename_filter",
                            "type": "text",
                            "default": "",
                            "mandatory": False,
                            "placeholder": "e.g. xrays_.*.jpg",
                            "description": (
                                "Regular expression that filters the files to "
                                "be pulled based on their filenames. "
                                "Ensure that the filter is a valid regular "
                                "expression. If left empty, all files from "
                                "the directory will be retrieved. "
                            ),
                        },
                    ],
                }
            ],
        }
    ],
    "file_results": [
        {
            "label": "Preview File Details",
            "key": "file_count_result",
            "type": "file_count_result",
            "default": {},
            "mandatory": False,
            "description": (
                "Preview file results."
            ),
        }
    ],
}
