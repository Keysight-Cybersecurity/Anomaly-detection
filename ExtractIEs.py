from binascii import unhexlify
from pycrate_mobile.NAS5G import *
from pycrate_core.elt import Element
import logging
import pyshark
import pandas as pd
import copy
import os.path as path


captureFiles = [
	
	# 'pcap/ens20.pcap',
	# 'pcap/AMF_5_1_A.cap',
	# 'pcap/AMF_5_1_C.cap',
	'pcap/lo.pcap', # one UE from loadcore (benigne)
	'pcap/AMF_3_1.cap', #  replay from scac
]

extractFile = "data.csv"


def extractIEs(captureFiles):
		def getPathsFromNAS5G(element: Element) -> list[tuple[list[str], any]]:
			paths = []
			try:
				if element.CLASS in ["Envelope", "Alt", "Sequence"]:
					for next_item in element._content:
						if next_item.CLASS == 'Atom':
							if next_item._val is None and next_item._trans:
								continue
							path = next_item.fullname().split(".")
							val = next_item._val
							if isinstance(val, bytes):
								val = val.hex()
							paths.append((path, val))
							if next_item._name == "NASMessage" and isinstance(next_item._val, bytes):
								inner_pdu, err = parse_NAS5G(next_item._val)
								if inner_pdu and inner_pdu.CLASS in ["Envelope", "Alt", "Sequence"]:
									inner_paths = getPathsFromNAS5G(inner_pdu)
									for ipath, ival in inner_paths:
										paths.append((path + ipath, ival))
						elif next_item.CLASS in ['Envelope', 'Alt', 'Sequence']:
							paths += getPathsFromNAS5G(next_item)
						else:
							print(f"Class {next_item.CLASS} not handled.")
				else:
					print(f"Unhandled root element class: {element.CLASS}")
			except AttributeError as e:
				print(f"AttributeError: {e}")
			return paths

		pcap_files = captureFiles

		# A dict that maps NAS Type to a function that matches the target IE path
		target_fields = {
		"RES": lambda path: "RES" in path and path[-1] == "L",
		"5GSID": lambda path: "5GSID" in path and path[-1] == "L",
		"UESecCap": lambda path: "UESecCap" in path and path[-1] == "L",
		"NASSecAlgo": lambda path: "NASSecAlgo" in path and path[-1] == "IntegAlgo",
		"PayloadContainer": lambda path: "PayloadContainer" in path and path[-1] == "L" and path[-2] == "PayloadContainer",
		"PayloadContainerType": lambda path: "PayloadContainerType" in path and path[-1] == "V",
		# Add more as needed
		}

		def extract_basic_pdu_info(paths, packet_data, all_keys):
			epd_count = 0
			sechdr_count = 0
			type_count = 0
			GMMCause_count = 0
			seqn_recorded = False
			spare_count = 0

			for path, value in paths:
				key = path[-1]
				if key == "EPD":
					epd_count += 1
					epd_key = f"EPD_{epd_count}" if epd_count > 1 else "EPD"
					packet_data[epd_key] = value
					all_keys.add(epd_key)
					print(f"{epd_key}: {value}")

				elif path[-1] == 'spare' and (path[-2] == '5GMMHeader' or path[-2] == "5GMMHeaderSec"):
					spare_count += 1
					spare_key = f"spare_{spare_count}" if spare_count > 1 else "spare"
					packet_data[spare_key] = value
					all_keys.add(spare_key)
					print(f"{spare_key}: {value}")

				elif key == "SecHdr":
					sechdr_count += 1
					sechdr_key = f"SecHdr_{sechdr_count}" if sechdr_count > 1 else "SecHdr"
					packet_data[sechdr_key] = value
					all_keys.add(sechdr_key)
					print(f"{sechdr_key}: {value}")

				elif key == "Seqn" and not seqn_recorded:
					packet_data["Seqn"] = value
					all_keys.add("Seqn")
					print(f"Seqn: {value}")
					seqn_recorded = True

				elif path[-2] == '5GMMHeader' and path[-1] == 'Type':
					type_count += 1
					type_key = f"Type_{type_count}" if type_count > 1 else "Type"
					packet_data[type_key] = value
					all_keys.add(type_key)
					print(f"{type_key}: {value}")

				elif key == "5GMMCause":
					GMMCause_count += 1
					GMMCause_key = f"5GMMCause_{GMMCause_count}" if GMMCause_count > 1 else "5GMMCause"
					packet_data[GMMCause_key] = value
					all_keys.add(GMMCause_key)
					print(f"{GMMCause_key}: {value}")

				for field_name, match_fn in target_fields.items():
					if match_fn(path):
						packet_data[field_name] = str(value)
						all_keys.add(field_name)
						print(f"{field_name}: {value}")

			def collect_fields(field_name, subfields):
				field_map = {sub: None for sub in subfields}
				for path, value in paths:
					if field_name in path:
						last = path[-1]
						if last in field_map:
							field_map[last] = int(value)

				if all(v is not None for v in field_map.values()):
					if field_name in ["NAS_KSI", "5GSRegType"]:
						one_bit = field_map.get("FOR", field_map.get("TSC", 0)) & 0b1
						three_bits = field_map["Value"] & 0b111
						combined = (one_bit << 3) | three_bits
						return [combined]
					elif field_name == "DeregistrationType":
						switch_off = field_map["SwitchOff"] & 0b1
						rereg = field_map["ReregistrationRequired"] & 0b1
						access_type = field_map["AccessType"] & 0b11
						byte_val = (switch_off << 3) | (rereg << 2) | access_type
						return [byte_val]
				return []  # Return nothing if not all required subfields are found

			# Only assign if fields are found
			nas_ksi_val = collect_fields("NAS_KSI", ["TSC", "Value"])
			if nas_ksi_val:
				packet_data["NAS_KSI"] = nas_ksi_val[0]
				all_keys.add("NAS_KSI")
				print(f"NAS_KSI: {nas_ksi_val[0]}")

			reg_type_val = collect_fields("5GSRegType", ["FOR", "Value"])
			if reg_type_val:
				packet_data["5GSRegType"] = reg_type_val[0]
				all_keys.add("5GSRegType")
				print(f"5GSRegType: {reg_type_val[0]}")

			dereg_type_val = collect_fields("DeregistrationType", ["SwitchOff", "ReregistrationRequired", "AccessType"])
			if dereg_type_val:
				packet_data["DeregistrationType"] = dereg_type_val[0]
				all_keys.add("DeregistrationType")
				print(f"DeregistrationType: {dereg_type_val[0]}")

			return packet_data

		packet_data_list = []
		all_keys = set()

		for file_path in pcap_files:
			print(f"Processing {file_path} ...")
			capture_file = pyshark.FileCapture(
				file_path,
				include_raw=True,
				display_filter='nas-5gs and not http and not http2 and not http3 and not json',
				use_ek=True,
				keep_packets=False
			)

			for wr_packet in capture_file:
				try:
					packet_data = {}
					time = wr_packet.frame_info.time.relative

					amf_field = wr_packet.ngap.get_field('AMF.UE.NGAP.ID')

					ip_source = wr_packet.ip.src.value
					procedureCode = int(wr_packet.ngap.procedureCode.value)

					if hasattr(wr_packet, 'ngap') and hasattr(wr_packet.ngap, 'NAS_PDU'):
						raw_data = wr_packet.ngap.NAS_PDU.raw
						nas_bytes = unhexlify(raw_data)
						pdu, err = parse_NAS5G(nas_bytes)

					packet_data["Time"] = time
					if amf_field:
						AMF_UE_NGAP_ID = amf_field.value
					else:
						AMF_UE_NGAP_ID = -1
					packet_data["AMF_UE_NGAP_ID"] = str(AMF_UE_NGAP_ID)
					packet_data["ip_source"] = ip_source
					packet_data["procedureCode"] = procedureCode

					if pdu and pdu.CLASS in ["Envelope", "Alt", "Sequence"]:
						print("=" * 10)
						print(f"time: {time}")
						print(f"AMF_UE_NGAP_ID: {AMF_UE_NGAP_ID}")
						print(f"ip_source: {ip_source}")
						print(f"procedureCode: {procedureCode}")

						paths = getPathsFromNAS5G(pdu)

						extracted = extract_basic_pdu_info(paths, packet_data, all_keys)

						packet_data_list.append(extracted)


				except Exception as e:
					print(f"Error parsing packet: {e}")

			capture_file.close()  # close after each file

		import csv


		# Add the static headers
		all_keys.update(["Time", "AMF_UE_NGAP_ID", "ip_source", "procedureCode"])

		# Use the first packet's key order as the preferred order
		if packet_data_list:
			first_keys_order = list(packet_data_list[0].keys())
			# Include any new keys discovered in later packets (to avoid missing columns)
			for pkt in packet_data_list[1:]:
				for k in pkt.keys():
					if k not in first_keys_order:
						first_keys_order.append(k)
		else:
			first_keys_order = []

		# Normalize all packet dicts to have all columns (preserve order)
		normalized_data = []
		for packet in packet_data_list:
			normalized_packet = {key: packet.get(key, "") for key in first_keys_order}
			normalized_data.append(normalized_packet)

		# Convert to DataFrame using pandas
		df = pd.DataFrame(normalized_data)

		# Save to CSV with comma as delimiter
		df.to_csv("data.csv", index=False, sep=";")



extractIEs(captureFiles)