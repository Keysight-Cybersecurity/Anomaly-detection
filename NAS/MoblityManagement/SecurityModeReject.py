class SecurityModeReject:
	mandatoryIEs = {
		'5GMMHeader': {'EPD': 126, 'spare': 0, 'SecHdr': 0, 'Type': 95},
		'5GMMCause': 1
	}

	def __init__(self):
		pass

	def isValidEPD(value):
		return True if value == SecurityModeReject.mandatoryIEs['5GMMHeader']['EPD'] else False

	def isValidSpare(value):
		return True if value == SecurityModeReject.mandatoryIEs['5GMMHeader']['spare'] else False

	def isValidSecHdr(value):
		return True if value == SecurityModeReject.mandatoryIEs['5GMMHeader']['SecHdr'] else False

	def isValidCause(value):
		return False if value is None or value.bit_length()/8 > SecurityModeReject.mandatoryIEs['5GMMCause'] else True
