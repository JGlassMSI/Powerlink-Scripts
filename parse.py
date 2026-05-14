import asyncio

import pyshark

# https://pyshark-packet-analysis.readthedocs.io/en/latest/
# https://github.com/KimiNewt/pyshark


def bitvals_to_dict(bvc) -> dict[int, int]:
    result = {}
    for i, bitval in enumerate(bvc.all_fields):
        result[i] = int(bitval.raw_value)
    return result

if __name__ == "__main__":
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    capture = pyshark.FileCapture(r'C:\Users\trex\Documents\Energy\Powerlink\Captures\small_m_test_5_14-2.pcapng')
    for i, packet in enumerate(capture):
        if hasattr(packet, 'tcp') and 'MODBUS' in str(packet.layers):
            mod = packet['MODBUS']
            if mod.func_code == "1":
                pass

            