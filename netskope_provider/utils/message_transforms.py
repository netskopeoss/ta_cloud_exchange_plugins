"""Custom message transforms for Cloud Pub/Sub Lite."""
import os
import time
import pickle
from typing import Tuple
from uuid import uuid4
from google.api_core.exceptions import InvalidArgument
from google.protobuf.timestamp_pb2 import Timestamp  # pytype: disable=pyi-error
from google.pubsub_v1 import PubsubMessage
from google.cloud.pubsublite_v1 import SequencedMessage
from google.cloud.pubsublite.cloudpubsub.message_transformer import MessageTransformer

from google.cloud.pubsublite.internal import fast_serialize
from google.cloud.pubsublite_v1 import AttributeValues, PubSubMessage

PUBSUB_LITE_EVENT_TIME = "x-goog-pubsublite-event-time"

def _encode_attribute_event_time_proto(ts: Timestamp) -> str:
    return fast_serialize.dump([ts.seconds, ts.nanos])

def _parse_attributes(values: AttributeValues) -> Tuple[str, bool]:
    if not len(values.values) == 1:
        raise InvalidArgument(
            "Received an unparseable message with multiple values for an attribute."
        )
    value: bytes = values.values[0]
    try:
        return value.decode("utf-8"), False
    except UnicodeError:
        # raise InvalidArgument(
        #     "Received an unparseable message with a non-utf8 attribute."
        # )
        # Replace non-utf8 characters with '?'
        print("Received an unparseable message with a non-utf8 attribute. Replaced with '?'.")
        return value.decode("utf-8", errors="replace"), True


def _to_cps_publish_message_proto(
    source: PubSubMessage.meta.pb,
) -> PubsubMessage.meta.pb:
    out = PubsubMessage.meta.pb()
    is_unicode_decode_error = False
    try:
        out.ordering_key = source.key.decode("utf-8")
    except UnicodeError:
        # raise InvalidArgument("Received an unparseable message with a non-utf8 key.")
        # Replace non-utf8 characters with '?'
        out.ordering_key = source.key.decode("utf-8", errors="replace")
        print("Received an unparseable message with a non-utf8 key. Replaced with '?'.")
        is_unicode_decode_error = True
    if PUBSUB_LITE_EVENT_TIME in source.attributes:
        raise InvalidArgument(
            "Special timestamp attribute exists in wire message. Unable to parse message."
        )
    out.data = source.data
    for key, values in source.attributes.items():
        out.attributes[key], unicode_decode_error = _parse_attributes(values)
        is_unicode_decode_error = is_unicode_decode_error or unicode_decode_error

    # Adding is_unicode_decode_error to attributes
    out.attributes["is_unicode_decode_error"] = str(is_unicode_decode_error).lower()
    out.attributes["unparseable_message_file_path"] = ""

    if source.HasField("event_time"):
        out.attributes[PUBSUB_LITE_EVENT_TIME] = _encode_attribute_event_time_proto(
            source.event_time
        )
    return out


def to_cps_subscribe_message(source: SequencedMessage) -> PubsubMessage:
    """Converts a SequencedMessage to a PubsubMessage."""
    source_pb = source._pb
    try:
        out_pb = _to_cps_publish_message_proto(source_pb.message)
        out_pb.publish_time.CopyFrom(source_pb.publish_time)
        out = PubsubMessage()
        out._pb = out_pb
        # Dump the invalid message to a file
        if out_pb.attributes["is_unicode_decode_error"] == "true":
            try:
                default_base_path = "/opt/netskope/plugins/custom_plugins"
                base_path = os.getenv("INVALID_WEBTX_MESSAGE_STORE_DIR", default_base_path)
                os.makedirs(base_path, exist_ok=True)
                fname = f"invalid_{str(uuid4())}_at_{int(time.time())}.pickle"
                file_path = os.path.join(base_path, fname)
                with open(file_path, "wb") as f:
                    print(f"Received an unparseable message. Writing it to file {fname}...")
                    pickle.dump(source, f)
                out.attributes["unparseable_message_file_path"] = file_path
            except Exception as e:
                print(f"Error occurred while writing unparseable message to file: {str(e)}")
        return out
    except Exception:
        raise


message_transformer = MessageTransformer.of_callable(to_cps_subscribe_message)
