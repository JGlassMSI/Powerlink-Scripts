import asyncio
from dataclasses import dataclass
from datetime import datetime
import pickle
from typing import TypeAlias

import pyshark

# https://pyshark-packet-analysis.readthedocs.io/en/latest/
# https://github.com/KimiNewt/pyshark

PanelCoilState: TypeAlias = dict[str, str]

class NiceDateTime(datetime):
    def __repr__(self) -> str:
        return self.ctime()

@dataclass(slots=True)
class ModbusPacketData :
    time: NiceDateTime
    number: int
    func_code: int
    state: PanelCoilState
    _packet: pyshark.packet.packet.Packet #type: ignore
    exception: str | None = None

    def __repr__(self) -> str:
        if self.exception:
            state_string = " - "
        else:
            if self.state:
                key, value = list(self.state.items())[0]
                state_string = f"{key} : {"ON" if "ff" in value else "OFF"}"
            else:
                state_string = " - "
        return f"{self.number: <6} ModbusPacket @ {self.time.isoformat(): <25} func:{self.func_code: <2} state:{state_string: <20} {f'exc:{self.exception}' if self.exception else '': <20}"

def parse_packet_data_from_file(filename: str) -> list[ModbusPacketData]:
    capture = pyshark.FileCapture(filename, display_filter="modbus")

    all_modbus_packets: list[ModbusPacketData] = []
    
    for i, packet in enumerate(capture):
        if hasattr(packet, 'tcp') and 'MODBUS' in str(packet.layers):
            data: PanelCoilState = {}
            exception = None

            mod_layer = packet['MODBUS']
            if mod_layer.func_code == "1": # read coils
                if hasattr(mod_layer, "bitnum") and hasattr(mod_layer, "bitval"):  
                    for num, val in zip(mod_layer.bitnum.all_fields, mod_layer.bitval.all_fields):
                        coil_number = num.showname_value
                        value = "1" if val.showname_value == 'True' else "0"
                        data[coil_number] = value
            elif mod_layer.func_code == "5": # write single coil
                if hasattr(mod_layer, "exception_code"):
                    exception = mod_layer.exception_code
                else:
                    data[mod_layer.reference_num] = mod_layer.data

            packet_data = ModbusPacketData(
                time = NiceDateTime.fromisoformat(packet.sniff_time.isoformat()),
                number = packet.number,
                state = data,
                func_code = int(mod_layer.func_code),
                _packet = packet,
                exception = exception
            )
    
            all_modbus_packets.append(packet_data)
        if not i % 100: print(i)
    return all_modbus_packets



if __name__ == "__main__":
    # As of Python 3.??, asyncio.get_event_loop doesn't start one automatically
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)


    filename =r"C:\Users\trex\Documents\Energy\Powerlink\Captures\overnight_func_5.pcapng"
    
    modbus_packets = parse_packet_data_from_file(filename)
    
    for packet in modbus_packets:
        print(packet)
