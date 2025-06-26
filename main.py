import pandas as pd

from NAS.NASService import NASService
from NAS.function import extractIEs


captureFiles = [
	'pcap/AMF_3_1.cap', #  replay from scac
	# 'pcap/ens20.pcap',
	# 'pcap/AMF_5_1_A.cap',
	# 'pcap/AMF_5_1_C.cap',
	'pcap/lo.pcap', # one UE from loadcore (benigne)
]

extractFile = "data.csv"
resultFile = "resultFile.csv"
service = NASService()
# service.extractIEs()
extractIEs(captureFiles)

df = pd.read_csv(extractFile, dtype=str)
df.fillna(-1, inplace=True)

def convert_float_int(val):
	if isinstance(val, float) and val.is_integer():
		return int(val)
	else:
		return val

df = df.map(convert_float_int)

# df.loc[2, 'Type'] = 89
# df.loc[3, 'Type'] = 86
# df.loc[4, 'Type'] = 89
# df.loc[5, 'Type'] = 86
# # print(df.columns)


df['valid_Type'] = df.apply(service.isValidType, axis=1)
df['valid_messageFlow'] = df.apply(service.hasValidMessageFlow, axis=1)
df['valid_min_auth_failure_rate'] = df.apply(service.hasValidMinAuthFailureRate, axis=1, args=(df,))

df['valid_SecHdr'] = df.apply(service.isValidSecHdr, axis=1)
df['valid_EPD'] = df.apply(service.isValidEPD, axis=1)
df['valid_spare'] = df.apply(service.isValidSpare, axis=1)

df['valid_secrFlow'] = df.apply(service.hasValidSecrFlow, axis=1)
df['valid_Seqn'] = df.apply(service.isValidSeqn, axis=1)

df['valid_5GSID'] = df.apply(service.isValid5GSID, axis=1)
df['valid_PayloadContainer'] = df.apply(service.isValidPayloadContainer, axis=1)

df['valid_NAS_KSI'] = df.apply(service.isValidNASKSI, axis=1)
df['valid_5GSRegType'] = df.apply(service.isValid5GSRegType, axis=1)
df['valid_PayloadContainerType'] = df.apply(service.isValidPayloadContainerType, axis=1)
df['valid_ServiceType'] = df.apply(service.isValidServiceType, axis=1)
df['valid_DeregistrationType'] = df.apply(service.isValidDeregistrationType, axis=1)

# df['valid_5GMMCause'] = df.apply(service.isValidCause, axis=1)
# df['valid_EAPmsg'] = df.apply(service.isValidEAP, axis=1)
# df['valid_NSSAI'] = df.apply(service.isValidNSSAI, axis=1)
# df['valid_PRTI'] = df.apply(service.isValidPRTI, axis=1)
# df['valid_RequestParameters'] = df.apply(service.isValidRequestParameters, axis=1)

# df['valid_ABBA'] = df.apply(service.isValidABBA, axis=1)
# df['valid_UESecCap'] = df.apply(service.isValidUESecCap, axis=1)
# df['valid_NASSecAlgo'] = df.apply(service.isValidNASSecAlgo, axis=1)
# df['valid_AccessType'] = df.apply(service.isValidAccessType, axis=1)
# df['valid_ResponseParameters'] = df.apply(service.isValidResponseParameters, axis=1)

df['label'] = df.apply(service.label, axis=1)

df.to_csv(resultFile, index=False, sep=";")
print(df)

print("================================= CHECK COMPLETED =================================")

