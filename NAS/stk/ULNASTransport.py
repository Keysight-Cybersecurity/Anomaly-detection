class ULNASTransport:
	mandatoryIEs = {'5GMMHeader': {'EPD': 126, 'spare': 0, 'SecHdr': 0, 'Type': 103},
					'spare': 0,
					'PayloadContainerType': 0.5,
					'PayloadContainer': list(range(0, 65537))
					}

	def __init__(self):
		pass

	def isValidEPD(value):
		return True if value == ULNASTransport.mandatoryIEs['5GMMHeader']['EPD'] else False

	def isValidSpare(value):
		return True if value == ULNASTransport.mandatoryIEs['5GMMHeader']['spare'] else False

	def isValidSecHdr(value):
		return True if value == ULNASTransport.mandatoryIEs['5GMMHeader']['SecHdr'] else False

	def isValidSpareBody(value):
		return True if value == ULNASTransport.mandatoryIEs['spare'] else False

	def isValidPayloadContainer(value):
		return False if value is None or value not in ULNASTransport.mandatoryIEs['PayloadContainer'] else True

	def isValidPayloadContainerType(value):
		return False if value is None or value.bit_length()/8 > ULNASTransport.mandatoryIEs['PayloadContainerType'] else True
