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
"""

def one_or_more(
    schema: dict, unique_items: bool = True, min: int = 1, max: int = None
) -> dict:
    """
    Helper function to construct a schema that validates items matching
    `schema` or an array containing items matching `schema`.

    :param schema: The schema to use
    :param unique_items: Flag if array items should be unique
    :param min: Correlates to ``minLength`` attribute of JSON Schema array
    :param max: Correlates to ``maxLength`` attribute of JSON Schema array
    """
    multi_schema = {
        "type": "array",
        "items": schema,
        "minItems": min,
        "uniqueItems": unique_items,
    }
    if max:
        multi_schema["maxItems"] = max
    return {"oneOf": [multi_schema, schema]}


def list_to_commas(list_of_args) -> str:
    """
    Converts a list of items to a comma separated list. If ``list_of_args`` is
    not a list, just return it back

    :param list_of_args: List of items
    :return: A string representing a comma separated list.
    """
    if isinstance(list_of_args, list):
        return ",".join(list_of_args)
    return list_of_args
    # todo change or create a new util that handle conversion to list as well
