"""
BSD 3-Clause License

Copyright (c) 2021, Netskope OSS
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice,
   this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its
   contributors may be used to endorse or promote products derived from
   this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
POSSIBILITY OF SUCH DAMAGE.

AWS CloudWatch CLS Plugin batch manager.

Splits the transformed log lines into batches that fit the PutLogEvents
limits: at most 10,000 events and at most 1,048,576 bytes per request,
where every event also costs 26 bytes of overhead, and a single event can
not be larger than 1 MB (AWS raised this from 256 KB on
2025-04-02).
"""

from typing import List, Tuple

from .constants import (
    MAX_BATCH_SIZE_BYTES,
    MAX_EVENT_SIZE_BYTES,
    MAX_EVENTS_PER_BATCH,
    PER_EVENT_OVERHEAD_BYTES,
)


class AWSCloudWatchBatchManager(object):
    """Build PutLogEvents batches that stay inside the AWS limits."""

    def __init__(self, logger, log_prefix):
        """Initialize AWSCloudWatchBatchManager.

        Args:
            logger: Logger object.
            log_prefix (str): Log prefix string.
        """
        self.logger = logger
        self.log_prefix = log_prefix

    @staticmethod
    def get_event_size(message: str) -> int:
        """Return the size AWS charges for one log event.

        Args:
            message (str): Log event message.

        Returns:
            int: UTF-8 byte length plus the per event overhead.
        """
        return len(message.encode("utf-8")) + PER_EVENT_OVERHEAD_BYTES

    def build_batches(
        self,
        messages: List[str],
        source_index: List[int],
        timestamp_ms: int,
        data_type: str,
        subtype: str,
    ) -> Tuple[List[List[dict]], List[int], int]:
        """Split the log lines into batches ready for PutLogEvents.

        Args:
            messages (List[str]): Transformed log lines.
            source_index (List[int]): Position of each message in the
                caller's transformed_data list. Needed so push() can
                trim the list at the first batch that fails.
            timestamp_ms (int): Event time in milliseconds, the same for
                every event of this push.
            data_type (str): Data type being pushed.
            subtype (str): Subtype being pushed.

        Returns:
            Tuple[List[List[dict]], List[int], int]: The batches, the
                source index of each batch's first event, and the number
                of log(s) skipped for being larger than the AWS limit
                for a single event.
        """
        batches = []
        batch_starts = []
        batch = []
        batch_bytes = 0
        batch_start = None
        oversize_count = 0

        for position, (message, index) in enumerate(
            zip(messages, source_index), start=1
        ):
            size = self.get_event_size(message)

            if size > MAX_EVENT_SIZE_BYTES:
                oversize_count += 1
                self.logger.warn(
                    f"{self.log_prefix}: [{data_type}][{subtype}] Skipped"
                    f" log number {position} of {len(messages)} because"
                    f" its size {size} bytes is larger than the AWS limit"
                    f" of {MAX_EVENT_SIZE_BYTES} bytes for a single log"
                    " event."
                )
                continue

            if batch and (
                len(batch) + 1 > MAX_EVENTS_PER_BATCH
                or batch_bytes + size > MAX_BATCH_SIZE_BYTES
            ):
                batches.append(batch)
                batch_starts.append(batch_start)
                batch = []
                batch_bytes = 0
                batch_start = None

            if not batch:
                batch_start = index
            batch.append({"timestamp": timestamp_ms, "message": message})
            batch_bytes += size

        if batch:
            batches.append(batch)
            batch_starts.append(batch_start)

        # PutLogEvents needs the events in time order.
        for current_batch in batches:
            current_batch.sort(key=lambda event: event["timestamp"])

        return batches, batch_starts, oversize_count

    @staticmethod
    def count_rejected_events(response: dict, batch_size: int) -> int:
        """Count the log(s) AWS rejected inside an accepted batch.

        AWS reports the rejected log(s) as index ranges. The ranges can
        overlap, so the indexes are collected in a set before counting.

        Args:
            response (dict): PutLogEvents response.
            batch_size (int): Number of events sent in the batch.

        Returns:
            int: Number of rejected log(s).
        """
        rejected_info = (response or {}).get("rejectedLogEventsInfo") or {}
        if not rejected_info:
            return 0

        rejected_indexes = set()

        too_new_start = rejected_info.get("tooNewLogEventStartIndex")
        if isinstance(too_new_start, int):
            rejected_indexes.update(range(too_new_start, batch_size))

        too_old_end = rejected_info.get("tooOldLogEventEndIndex")
        if isinstance(too_old_end, int):
            rejected_indexes.update(range(0, min(too_old_end, batch_size)))

        expired_end = rejected_info.get("expiredLogEventEndIndex")
        if isinstance(expired_end, int):
            rejected_indexes.update(range(0, min(expired_end, batch_size)))

        return len(rejected_indexes)
