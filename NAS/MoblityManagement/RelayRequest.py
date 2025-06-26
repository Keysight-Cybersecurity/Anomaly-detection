class RelayRequest:
	mandatoryIEs = {'5GMMHeader': {'EPD': 126, 'spare': 0, 'SecHdr': 0, 'Type': 1},
					'PRTI': 1,
					'RequestParameters': list(range(21, 65537)),
					}


	def __init__(self):
		pass

	def isValidEPD(value):
		return True if value == RelayRequest.mandatoryIEs['5GMMHeader']['EPD'] else False

	def isValidSpare(value):
		return True if value == RelayRequest.mandatoryIEs['5GMMHeader']['spare'] else False

	def isValidSecHdr(value):
		return True if value == RelayRequest.mandatoryIEs['5GMMHeader']['SecHdr'] else False

	def isValidPRTI(value):
		return False if value is None or value.bit_length()/8 > RelayRequest.mandatoryIEs['PRTI'] else True

	def isValidRequestParameters(value):
		return False if value is None or value not in RelayRequest.mandatoryIEs['RequestParameters'] else True

