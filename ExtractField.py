from binascii import unhexlify
from pycrate_mobile.NAS5G import *
from pycrate_core.elt import Element
import logging
import pyshark
import pandas as pd
import copy
import os.path as path

# Configuration
CONFIG = {
    'capture_files': [
        # 'pcap/lo.pcap', #Benign
        'pcap/AMF_3_1.cap', #Replay
    ],
    'output_file': 'dataheaderTest.csv',
    'delimiter': ';',
    'display_filter': 'nas-5gs and not http and not http2 and not http3 and not json'
}

# Constants
NAS_5G_CLASSES = ["Envelope", "Alt", "Sequence"]
DEFAULT_AMF_ID = -1


class NAS5GExtractor:
    def __init__(self, config=None):
        self.config = config or CONFIG
        self.packet_data_list = []
        self.all_keys = set()
        
    def get_paths_from_nas5g(self, element: Element) -> list[tuple[list[str], any]]:
        """Recursively extract paths and values from NAS5G elements."""
        paths = []
        try:
            if element.CLASS in NAS_5G_CLASSES:
                for next_item in element._content:
                    if next_item.CLASS == 'Atom':
                        if next_item._val is None and next_item._trans:
                            continue
                        path = next_item.fullname().split(".")
                        val = next_item._val
                        if isinstance(val, bytes):
                            val = val.hex()
                        paths.append((path, val))
                        
                        # Handle nested NAS messages
                        if next_item._name == "NASMessage" and isinstance(next_item._val, bytes):
                            inner_pdu, err = parse_NAS5G(next_item._val)
                            if inner_pdu and inner_pdu.CLASS in NAS_5G_CLASSES:
                                inner_paths = self.get_paths_from_nas5g(inner_pdu)
                                for ipath, ival in inner_paths:
                                    paths.append((path + ipath, ival))
                                    
                    elif next_item.CLASS in NAS_5G_CLASSES:
                        paths += self.get_paths_from_nas5g(next_item)
                    else:
                        print(f"Class {next_item.CLASS} not handled.")
            else:
                print(f"Unhandled root element class: {element.CLASS}")
        except AttributeError as e:
            print(f"AttributeError: {e}")
        return paths

    def extract_basic_fields(self, paths, packet_data):
        """Extract basic PDU information from paths."""
        counters = {
            'epd': 0,
            'sechdr': 0,
            'type': 0,
            'spare': 0
        }
        seqn_recorded = False

        for path, value in paths:
            key = path[-1]
            
            # Handle EPD fields
            if key == "EPD" and (path[-2] == '5GMMHeader' or path[-2] == "5GMMHeaderSec"):
                packet_data["EPD"] = value
                self.all_keys.add("EPD")
                print('EPD', value)

            # Handle spare fields
            elif key == 'spare' and (path[-2] == '5GMMHeader' or path[-2] == "5GMMHeaderSec"):
                packet_data["spare"] = value
                self.all_keys.add("spare")
                print('spare', value)

            # Handle SecHdr
            if key == "SecHdr" and (path[-2] == '5GMMHeader' or path[-2] == "5GMMHeaderSec"):
                

                counters['sechdr'] += 1
                sechdr_key = f"SecHdr_{counters['sechdr']}" if counters['sechdr'] > 1 else "SecHdr"
                packet_data[sechdr_key] = value
                self.all_keys.add(sechdr_key)
                print(f"{sechdr_key}: {value}")

            # Handle Sequence number
            elif key == "Seqn" and not seqn_recorded:
                packet_data["Seqn"] = value
                self.all_keys.add("Seqn")
                print(f"Seqn: {value}")
                seqn_recorded = True

            # Handle Type fields
            elif len(path) >= 2 and path[-2] == '5GMMHeader' and key == 'Type':
                counters['type'] += 1
                type_key = f"Type_{counters['type']}" if counters['type'] > 1 else "Type"
                packet_data[type_key] = value
                self.all_keys.add(type_key)
                print(f"{type_key}: {value}")



    def process_packet(self, packet):
        """Process a single packet and extract NAS data."""
        try:
            packet_data = {}
            
            # Extract basic packet info
            time = packet.frame_info.time.relative
            amf_field = packet.ngap.get_field('AMF.UE.NGAP.ID')
            ip_source = packet.ip.src.value
            procedure_code = int(packet.ngap.procedureCode.value)

            # Get NAS PDU
            if hasattr(packet, 'ngap') and hasattr(packet.ngap, 'NAS_PDU'):
                raw_data = packet.ngap.NAS_PDU.raw
                nas_bytes = unhexlify(raw_data)
                pdu, err = parse_NAS5G(nas_bytes)
                
                if err:
                    print(f"NAS parsing error: {err}")
                    return None

                # Store basic packet data
                packet_data["Time"] = time
                packet_data["AMF_UE_NGAP_ID"] = str(amf_field.value if amf_field else DEFAULT_AMF_ID)
                packet_data["ip_source"] = ip_source
                packet_data["procedureCode"] = procedure_code

                if pdu and pdu.CLASS in NAS_5G_CLASSES:
                    print("=" * 10)
                    print(f"time: {time}")
                    print(f"AMF_UE_NGAP_ID: {packet_data['AMF_UE_NGAP_ID']}")
                    print(f"ip_source: {ip_source}")
                    print(f"procedureCode: {procedure_code}")

                    paths = self.get_paths_from_nas5g(pdu)
                    self.extract_basic_fields(paths, packet_data)

                    return packet_data
                    
        except Exception as e:
            print(f"Error parsing packet: {e}")
        return None

    def process_pcap_file(self, file_path):
        """Process a single PCAP file."""
        print(f"Processing {file_path} ...")
        
        try:
            capture_file = pyshark.FileCapture(
                file_path,
                include_raw=True,
                display_filter=self.config['display_filter'],
                use_ek=True,
                keep_packets=False
            )

            for packet in capture_file:
                processed_packet = self.process_packet(packet)
                if processed_packet:
                    self.packet_data_list.append(processed_packet)

            capture_file.close()
            
        except Exception as e:
            print(f"Error processing file {file_path}: {e}")

    def save_to_csv(self):
        """Save extracted data to CSV file."""
        if not self.packet_data_list:
            print("No data to save.")
            return

        # Add static headers
        self.all_keys.update(["Time", "AMF_UE_NGAP_ID", "ip_source", "procedureCode"])

        # Determine column order
        if self.packet_data_list:
            first_keys_order = list(self.packet_data_list[0].keys())
            for pkt in self.packet_data_list[1:]:
                for k in pkt.keys():
                    if k not in first_keys_order:
                        first_keys_order.append(k)
        else:
            first_keys_order = []

        # Normalize data
        normalized_data = []
        for packet in self.packet_data_list:
            normalized_packet = {key: packet.get(key, "") for key in first_keys_order}
            normalized_data.append(normalized_packet)

        # Create DataFrame and save
        df = pd.DataFrame(normalized_data)
        df.to_csv(self.config['output_file'], index=False, sep=self.config['delimiter'])
        print(f"Data saved to {self.config['output_file']}")

    def extract_nas_messages(self):
        """Main method to extract NAS messages from all PCAP files."""
        for file_path in self.config['capture_files']:
            self.process_pcap_file(file_path)
        
        self.save_to_csv()

# Main execution
if __name__ == "__main__":
    extractor = NAS5GExtractor()
    extractor.extract_nas_messages()