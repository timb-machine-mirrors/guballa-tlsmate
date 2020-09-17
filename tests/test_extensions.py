# -*- coding: utf-8 -*-
import pytest

import tlsclient.extensions as ext
from tlsclient.protocol import ProtocolData

def test_ServerNameIndication():
    data = ProtocolData().fromhex("00 00 00 0e 00 0c 00 00 09 6c 6f 63 61 6c 68 6f 73 74")
    sni = ext.Extension.deserialize(data)
    assert sni.host_name == "localhost"
    assert sni.serialize() == data
    sni = ext.ExtServerNameIndication(host_name="localhost")
    assert sni.serialize() == data

