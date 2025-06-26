class ControlPlaneServiceRequest:
	mandatoryIEs = {'5GMMHeader': {'EPD': 126, 'spare': 0, 'SecHdr': 0, 'Type': 79},
					'NAS_KSI': 0.5,
					'ServiceType': 0.5,
					}


	def __init__(self):
		pass

	def isValidEPD(value):
		return True if value == ControlPlaneServiceRequest.mandatoryIEs['5GMMHeader']['EPD'] else False

	def isValidSpare(value):
		return True if value == ControlPlaneServiceRequest.mandatoryIEs['5GMMHeader']['spare'] else False

	def isValidSecHdr(value):
		return True if value == ControlPlaneServiceRequest.mandatoryIEs['5GMMHeader']['SecHdr'] else False

	def isValidNASKSI(value):
		return False if value is None or value.bit_length()/8 > ControlPlaneServiceRequest.mandatoryIEs['NAS_KSI'] else True

	def isValidServiceType(value):
		return False if value is None or value.bit_length()/8 > ControlPlaneServiceRequest.mandatoryIEs['ServiceType'] else True

