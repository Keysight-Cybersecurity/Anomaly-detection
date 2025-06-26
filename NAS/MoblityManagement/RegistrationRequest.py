class RegistrationRequest:
	mandatoryIEs = {
		'5GMMHeader': {'EPD': 126, 'spare': 0, 'SecHdr': 0, 'Type': 65},
		'NAS_KSI': 4,
		'5GSRegType': 4,
		'5GSID': {'min': 3},
	}

	def __init__(self):
		pass

	def isValidEPD(value):
		return True if value == RegistrationRequest.mandatoryIEs['5GMMHeader']['EPD'] else False

	def isValidSpare(value):
		return True if value == RegistrationRequest.mandatoryIEs['5GMMHeader']['spare'] else False

	def isValidSecHdr(value):
		return True if value == RegistrationRequest.mandatoryIEs['5GMMHeader']['SecHdr'] else False

	def isValid5GSRegType(value):
		if value is None:
			return False
		return value >= 0 and value.bit_length() <= RegistrationRequest.mandatoryIEs['5GSRegType']

	
	def isValidNASKSI(value):
		if value is None:
			return False
		return value >= 0 and value.bit_length() <= RegistrationRequest.mandatoryIEs['NAS_KSI']

	def isValid5GSID(value):
		return False if value < RegistrationRequest.mandatoryIEs['5GSID']['min'] else True
