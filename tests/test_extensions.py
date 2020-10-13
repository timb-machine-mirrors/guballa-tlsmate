# -*- coding: utf-8 -*-

import tlsclient.extensions as ext


def test_ServerNameIndication():
    data = bytes.fromhex("00 00 00 0e 00 0c 00 00 09 6c 6f 63 61 6c 68 6f 73 74")
    sni, offset = ext.Extension.deserialize(data, 0)
    assert offset == len(data)
    assert sni.host_name == "localhost"
    assert sni.serialize(None) == data
    sni = ext.ExtServerNameIndication(host_name="localhost")
    assert sni.serialize(None) == data
