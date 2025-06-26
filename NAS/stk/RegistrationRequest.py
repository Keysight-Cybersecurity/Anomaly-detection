class RegistrationRequest:
	mandatoryIEs = {
		'5GMMHeader': {'EPD': 126, 'spare': 0, 'SecHdr': 0, 'Type': 65},
		'NAS_KSI': 0.5,
		'5GSRegType': 0.5,
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
		return False if value is None or value.bit_length()/8 > RegistrationRequest.mandatoryIEs['5GSRegType'] else True

	def isValidNASKSI(value):
		return False if value is None or value.bit_length()/8 > RegistrationRequest.mandatoryIEs['NAS_KSI'] else True

	def isValid5GSID(value):
		return False if value < RegistrationRequest.mandatoryIEs['5GSID']['min'] else True
