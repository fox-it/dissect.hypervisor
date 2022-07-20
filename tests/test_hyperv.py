from dissect.hypervisor.descriptor.hyperv import HyperVFile


def test_vmcx(vmcx):
    hf = HyperVFile(vmcx)

    assert hf.header is hf.headers[0]
    assert hf.version == 0x400
    assert len(hf.replay_logs) == 1
    assert len(hf.object_tables) == 1
    assert len(hf.key_tables) == 8

    obj = hf.as_dict()
    assert set(obj.keys()) == {"configuration"}
    assert len(obj["configuration"].keys()) == 27
    assert len(obj["configuration"]["manifest"].keys()) == 39
    assert len(obj["configuration"]["properties"].keys()) == 11
    assert len(obj["configuration"]["settings"].keys()) == 6


def test_vmrs(vmrs):
    hf = HyperVFile(vmrs)

    assert hf.header is hf.headers[0]
    assert hf.version == 0x400
    assert len(hf.replay_logs) == 1
    assert len(hf.object_tables) == 1
    assert len(hf.key_tables) == 2

    obj = hf.as_dict()
    target = {
        "configuration": {
            "properties": {"version": 2304},
            "global_settings": {
                "metrics": {
                    "devicetype": {
                        "guid": "83F8638B-8DCA-4152-9EDA-2CA8B33039B4",
                        "deviceinstance": {
                            "guid": "83F8638B-8DCA-4152-9EDA-2CA8B33039B4",
                            "metric": {
                                "typecode": "4E1D459F-7861-46A4-887C-B64397C97E1B;0\\0\\L",
                                "value": 0,
                                "enabled": False,
                                "starttime": 0,
                                "lastcomputedtime": 0,
                                "peaktime": 0,
                                "poolid": "",
                                "resourcetypeid": "70BB60D2-A9D3-46AA-B654-3DE53004B4F8",
                            },
                        },
                    }
                }
            },
            "_ac6b8dc1-3257-4a70-b1b2-a9c9215659ad_": {"VDEVVersion": 2048},
            "_e51b7ef6-4a7f-4780-aaae-d4b291aacd2e_": {"VDEVVersion": 512},
            "_83f8638b-8dca-4152-9eda-2ca8b33039b4_": {"VDEVVersion": 1792},
        }
    }
    assert obj == target
