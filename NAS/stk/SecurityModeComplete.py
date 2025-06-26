class SecurityModeComplete:
	mandatoryIEs = {
					'5GMMHeader': {'EPD': 126, 'spare': 0, 'SecHdr': 0, 'Type': 94},
					}

	def __init__(self):
		pass

	def isValidEPD(value):
		return True if value == SecurityModeComplete.mandatoryIEs['5GMMHeader']['EPD'] else False

	def isValidSpare(value):
		return True if value == SecurityModeComplete.mandatoryIEs['5GMMHeader']['spare'] else False

	def isValidSecHdr(value):
		return True if value == SecurityModeComplete.mandatoryIEs['5GMMHeader']['SecHdr'] else False