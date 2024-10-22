
"""
The operation can be: next, head, tail, resend, or a timestamp value.
"""
from enum import Enum

class Operation(Enum):
    OP_HEAD = "head"
    OP_TAIL = "tail"
    OP_NEXT = "next"
    OP_RESEND = "resend"
    OP_TIMESTAMP = "timestamp"
