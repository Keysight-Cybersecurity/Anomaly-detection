class RelayAuthenticationResponse:
	mandatoryIEs = {'5GMMHeader': {'EPD': 126, 'spare': 0, 'SecHdr': 0, 'Type': 1},
					'PRTI': 1,
					'EAPmsg': list(range(3, 1502)),
					}


	def __init__(self):
		pass

	def isValidEPD(value):
		return True if value == RelayAuthenticationResponse.mandatoryIEs['5GMMHeader']['EPD'] else False

	def isValidSpare(value):
		return True if value == RelayAuthenticationResponse.mandatoryIEs['5GMMHeader']['spare'] else False

	def isValidSecHdr(value):
		return True if value == RelayAuthenticationResponse.mandatoryIEs['5GMMHeader']['SecHdr'] else False

	def isValidPRTI(value):
		return False if value is None or value.bit_length()/8 > RelayAuthenticationResponse.mandatoryIEs['PRTI'] else True

	def isValidEAP(value):
		return False if value is None or value not in RelayAuthenticationResponse.mandatoryIEs['EAPmsg'] else True

