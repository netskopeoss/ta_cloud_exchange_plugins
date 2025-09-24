"""Linux File Share CFC plugin constants file."""

MODULE_NAME = "CFC"
PLUGIN_NAME = "Linux File Share CFC"
PLUGIN_VERSION = "1.0.0"
SUPPORTED_IMAGE_FILE_EXTENSIONS = [".bmp", ".dib", ".jpeg", ".jpg", ".jpe", ".jp2", ".png", ".webp", ".avif", ".pbm",
                                   ".pgm", ".ppm", ".pxm", ".pnm", ".pfm", ".sr", ".ras",  ".tiff", ".tif", ".exr",
                                   ".hdr", ".pic", ".zip", ".tgz"]
ALLOWED_FILE_COUNT = 10000
ALLOWED_FILE_SIZE = 83886080000
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