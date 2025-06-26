class RelayAccept:
	mandatoryIEs = {'5GMMHeader': {'EPD': 126, 'spare': 0, 'SecHdr': 0, 'Type': 1},
					'PRTI': 0,
					'ResponseParameters': 0,
					}


	def __init__(self):
		pass

	def isValidEPD(value):
		return True if value == RelayAccept.mandatoryIEs['5GMMHeader']['EPD'] else False

	def isValidSpare(value):
		return True if value == RelayAccept.mandatoryIEs['5GMMHeader']['spare'] else False

	def isValidSecHdr(value):
		return True if value == RelayAccept.mandatoryIEs['5GMMHeader']['SecHdr'] else False

	def isValidPRTI(value):
		return True

	def isValidResponseParameters(value):
		return True

