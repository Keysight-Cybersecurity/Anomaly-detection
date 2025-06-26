class SecurityModeComplete:
	mandatoryIEs = {
					'5GMMHeader': {'EPD': 126, 'spare': 0, 'SecHdr': 0, 'Type': 94},
					'NAS_KSI': 4,
					'5GSRegType': 4,
					}

	def __init__(self):
		pass

	def isValidEPD(value):
		return True if value == SecurityModeComplete.mandatoryIEs['5GMMHeader']['EPD'] else False

	def isValidSpare(value):
		return True if value == SecurityModeComplete.mandatoryIEs['5GMMHeader']['spare'] else False

	def isValidSecHdr(value):
		return True if value == SecurityModeComplete.mandatoryIEs['5GMMHeader']['SecHdr'] else False
	
	def isValidNASKSI(value):
		if value is None:
			return False
		return value >= 0 and value.bit_length() <= SecurityModeComplete.mandatoryIEs['NAS_KSI']
	
	def isValid5GSRegType(value):
		if value is None:
			return False
		return value >= 0 and value.bit_length() <= SecurityModeComplete.mandatoryIEs['5GSRegType']