class ServiceRequest:
	mandatoryIEs = {'5GMMHeader': {'EPD': 126, 'spare': 0, 'SecHdr': 0, 'Type': 76},
					'NAS_KSI': 0.5,
					'5GSID': 6,
					'ServiceType': 0.5,
					}


	def __init__(self):
		pass

	def isValidEPD(value):
		return True if value == ServiceRequest.mandatoryIEs['5GMMHeader']['EPD'] else False

	def isValidSpare(value):
		return True if value == ServiceRequest.mandatoryIEs['5GMMHeader']['spare'] else False

	def isValidSecHdr(value):
		return True if value == ServiceRequest.mandatoryIEs['5GMMHeader']['SecHdr'] else False

	def isValidServiceType(value):
		return False if value is None or value.bit_length()/8 > ServiceRequest.mandatoryIEs['ServiceType'] else True

	def isValidNASKSI(value):
		return False if value is None or value.bit_length()/8 > ServiceRequest.mandatoryIEs['NAS_KSI'] else True

	def isValid5GSID(value):
		return False if value is None or value != ServiceRequest.mandatoryIEs['5GSID'] else True

