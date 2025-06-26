class DeregistrationRequestUE:
	mandatoryIEs = {'5GMMHeader': {'EPD': 126, 'spare': 0, 'SecHdr': 0, 'Type': 69},
					'NAS_KSI': 0.5,
					'DeregistrationType': 0.5,
					'5GSID': {'min': 3}
					}

	def __init__(self):
		pass

	def isValidEPD(value):
		return True if value == DeregistrationRequestUE.mandatoryIEs['5GMMHeader']['EPD'] else False

	def isValidSpare(value):
		return True if value == DeregistrationRequestUE.mandatoryIEs['5GMMHeader']['spare'] else False

	def isValidSecHdr(value):
		return True if value == DeregistrationRequestUE.mandatoryIEs['5GMMHeader']['SecHdr'] else False

	def isValidNASKSI(value):
		return False if value is None or value.bit_length()/8 > DeregistrationRequestUE.mandatoryIEs['NAS_KSI'] else True

	def isValidDeregistrationType(value):
		return False if value is None or value.bit_length()/8 > DeregistrationRequestUE.mandatoryIEs['DeregistrationType'] else True

	def isValid5GSID(value):
		return False if value is None or value < DeregistrationRequestUE.mandatoryIEs['5GSID']['min'] else True
