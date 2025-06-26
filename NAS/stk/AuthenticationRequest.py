class AuthenticationRequest:
	mandatoryIEs = {
		'5GMMHeader': {'EPD': 126, 'spare': 0, 'SecHdr': 0, 'Type': 86},
		'NAS_KSI': 0,
		'spare': 0,
		'ABBA': 0,
	}

	def __init__(self):
		pass

	def isValidEPD(value):
		return True if value == AuthenticationRequest.mandatoryIEs['5GMMHeader']['EPD'] else False

	def isValidSpare(value):
		return True if value == AuthenticationRequest.mandatoryIEs['5GMMHeader']['spare'] else False

	def isValidSecHdr(value):
		return True if value == AuthenticationRequest.mandatoryIEs['5GMMHeader']['SecHdr'] else False

	def isValidSpareBody(value):
		return True if value == AuthenticationRequest.mandatoryIEs['spare'] else False

	def isValidNASKSI(value):
		return True

	def isValidABBA(value):
		return True

