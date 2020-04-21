#!/usr/bin/env python
"""OutputPlugin that sends Flow results to a HTTP GELF input.
Configuration values for this plugin can be found in
core/grr_response_core/config/output_plugins.py
The spec for GELF is taken from https://docs.graylog.org/en/3.2/pages/gelf.html
"""
from __future__ import absolute_import
from __future__ import division

from __future__ import unicode_literals

from urllib import parse as urlparse

import requests


from google.protobuf import json_format

from grr_response_core import config
from grr_response_core.lib import rdfvalue
from grr_response_core.lib.rdfvalues import structs as rdf_structs
from grr_response_core.lib.util.compat import json
from grr_response_proto import output_plugin_pb2
from grr_response_server import data_store
from grr_response_server import export
from grr_response_server import output_plugin
from grr_response_server.gui.api_plugins import flow as api_flow
import json


class GELFConfigurationError(Exception):
  """Error indicating a wrong or missing GELF configuration."""
  pass


class GELFOutputPluginArgs(rdf_structs.RDFProtoStruct):
  protobuf = output_plugin_pb2.GELFOutputPluginArgs
  rdf_deps = []


def _ToDict(rdfval):
  return json_format.MessageToDict(rdfval.AsPrimitiveProto(), float_precision=8)


class GELFOutputPlugin(output_plugin.OutputPlugin):
  """OutputPlugin that sends Flow results to Splunk Http Event Collector."""

  name = "gelf"
  description = "Send flow results to GELF input."
  args_type = GELFOutputPluginArgs

  def __init__(self, *args, **kwargs):
    """See base class."""
    super().__init__(*args, **kwargs)
    url = config.CONFIG["GELF.url"]

    if not url:
      raise GELFConfigurationError(
          "Cannot start GELFOutputPlugin, because GELF.url is not "
          "configured. Set it to the URL of your GELF input, "
          "e.g. 'https://logging-server.example.com:12201'.")
    self._url = url

  def ProcessResponses(self, state, responses):
    """See base class."""
    client_id = self._GetClientId(responses)
    flow_id = self._GetFlowId(responses)

    client = self._GetClientMetadata(client_id)
    flow = self._GetFlowMetadata(client_id, flow_id)

    payloads = [self._MakePayload(response, client, flow) for response in responses]

    self._SendPayloads(payloads)

  def _GetClientId(self, responses):
    client_ids = {msg.source.Basename() for msg in responses}
    if len(client_ids) > 1:
      raise AssertionError((
                             "ProcessResponses received messages from different Clients {}, which "
                             "violates OutputPlugin constraints.").format(client_ids))
    return client_ids.pop()

  def _GetFlowId(self, responses):
    flow_ids = {msg.session_id.Basename() for msg in responses}
    if len(flow_ids) > 1:
      raise AssertionError(
        ("ProcessResponses received messages from different Flows {}, which "
         "violates OutputPlugin constraints.").format(flow_ids))
    return flow_ids.pop()

  def _GetClientMetadata(self, client_id):
    info = data_store.REL_DB.ReadClientFullInfo(client_id)
    metadata = export.GetMetadata(client_id, info)
    metadata.timestamp = None  # timestamp is sent outside of metadata.
    return metadata

  def _GetFlowMetadata(self, client_id,
                       flow_id):
    flow_obj = data_store.REL_DB.ReadFlowObject(client_id, flow_id)
    return api_flow.ApiFlow().InitFromFlowObject(flow_obj)

  def _MakePayload(self, message,
                   client,
                   flow):

    if message.timestamp:
      time = message.timestamp.AsSecondsSinceEpoch()
    else:
      time = rdfvalue.RDFDatetime.Now().AsSecondsSinceEpoch()

    host = client.hostname or message.source.Basename()
    payload = {
      "version": "1.1",
      "host": host,
      "short_message": "GRR: " + str(host) + " -> " + str(flow.name),
      "full_message": "GRR flow " + str(flow.name) + " was run on host " + str(host),
      "timestamp": time,
      "_flow_name": flow.name
    }

    message_as_dict = _ToDict(message.payload)
    for key in message_as_dict.keys():
      payload['_' + str(key)] = message_as_dict[key]

    return payload

  def _SendPayloads(self, payloads):
    headers = {'Content-type': 'application/json'}
    for payload in payloads:
      response = requests.post(
          url=self._url, verify=False, data=json.dumps(payload), headers=headers)
      response.raise_for_status()
