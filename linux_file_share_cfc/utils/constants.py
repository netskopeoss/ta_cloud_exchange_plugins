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

Linux File Share CFC plugin constants file.
"""

MODULE_NAME = "CFC"
PLUGIN_NAME = "Linux File Share"
PLUGIN_VERSION = "1.1.0"
SUPPORTED_IMAGE_FILE_EXTENSIONS = [".bmp", ".dib", ".jpeg", ".jpg", ".jpe",
                                   ".jp2", ".png", ".webp", ".avif", ".pbm",
                                   ".pgm", ".ppm", ".pxm", ".pnm", ".pfm",
                                   ".sr", ".ras",  ".tiff", ".tif", ".exr",
                                   ".hdr", ".pic", ".zip", ".tgz"]
ALLOWED_FILE_COUNT = 10000
ALLOWED_FILE_SIZE = 80 * 1024 * 1024 * 1024
LINUX_FILE_SHARE_FIELDS = {
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
