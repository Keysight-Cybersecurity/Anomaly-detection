class AuthenticationResponse:
	mandatoryIEs = {
		'5GMMHeader': {'EPD': 126, 'spare': 0, 'SecHdr': 0, 'Type': 87},
		'RES': list(range(2, 17)),
	}

	def __init__(self):
		pass

	def isValidEPD(value):
		return True if value == AuthenticationResponse.mandatoryIEs['5GMMHeader']['EPD'] else False

	def isValidSpare(value):
		return True if value == AuthenticationResponse.mandatoryIEs['5GMMHeader']['spare'] else False

	def isValidSecHdr(value):
		return True if value == AuthenticationResponse.mandatoryIEs['5GMMHeader']['SecHdr'] else False
	
	def isValidRES(value):
		if value is None:
			return False
		if not isinstance(value, int):
			return False
		valid_range = AuthenticationResponse.mandatoryIEs['RES']
		return value in valid_range