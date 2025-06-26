class DLNASTransport:
	mandatoryIEs = {'5GMMHeader': {'EPD': 126, 'spare': 0, 'SecHdr': 0, 'Type': 104},
					'spare': 0,
					'PayloadContainerType': 0,
					'PayloadContainer': 0,
					}

	def __init__(self):
		pass

	def isValidEPD(value):
		return True if value == DLNASTransport.mandatoryIEs['5GMMHeader']['EPD'] else False

	def isValidSpare(value):
		return True if value == DLNASTransport.mandatoryIEs['5GMMHeader']['spare'] else False

	def isValidSecHdr(value):
		return True if value == DLNASTransport.mandatoryIEs['5GMMHeader']['SecHdr'] else False

	def isValidSpareBody(value):
		return True if value == DLNASTransport.mandatoryIEs['spare'] else False

	def isValidPayloadContainer(value):
		return True

	def isValidPayloadContainerType(value):
		return True
