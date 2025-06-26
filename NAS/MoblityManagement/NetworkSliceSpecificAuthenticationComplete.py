class NetworkSliceSpecificAuthenticationComplete:
	mandatoryIEs = {'5GMMHeader': {'EPD': 126, 'spare': 0, 'SecHdr': 0, 'Type': 81},
					'NSSAI': list(range(1, 5)),
					'EAPmsg': list(range(3, 1502)),
					}


	def __init__(self):
		pass

	def isValidEPD(value):
		return True if value == NetworkSliceSpecificAuthenticationComplete.mandatoryIEs['5GMMHeader']['EPD'] else False

	def isValidSpare(value):
		return True if value == NetworkSliceSpecificAuthenticationComplete.mandatoryIEs['5GMMHeader']['spare'] else False

	def isValidSecHdr(value):
		return True if value == NetworkSliceSpecificAuthenticationComplete.mandatoryIEs['5GMMHeader']['SecHdr'] else False

	def isValidNSSAI(value):
		return False if value is None or value not in NetworkSliceSpecificAuthenticationComplete.mandatoryIEs['NSSAI'] else True

	def isValidEAP(value):
		return False if value is None or value not in NetworkSliceSpecificAuthenticationComplete.mandatoryIEs['EAPmsg'] else True

