class SecurityModeCommand:
	mandatoryIEs = {
					'5GMMHeader': {'EPD': 126, 'spare': 0, 'SecHdr': 0, 'Type': 93},
					'spare': 0,
					'NASSecAlgo': 0,
					'NAS_KSI': 0,
					'UESecCap': 0
	}

	def __init__(self):
		pass

	def isValidEPD(value):
		return True if value == SecurityModeCommand.mandatoryIEs['5GMMHeader']['EPD'] else False

	def isValidSpare(value):
		return True if value == SecurityModeCommand.mandatoryIEs['5GMMHeader']['spare'] else False

	def isValidSecHdr(value):
		return True if value == SecurityModeCommand.mandatoryIEs['5GMMHeader']['SecHdr'] else False

	def isValidSpareBody(value):
		return True if value == SecurityModeCommand.mandatoryIEs['spare'] else False

	def isValidNASKSI(value):
		return True

	def isValidNASSecAlgo(value):
		return True

	def isValidUESecCap(value):
		return True

