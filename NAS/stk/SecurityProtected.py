class SecurityProtected:
	mandatoryIEs = {
		'5GMMHeaderSec': {'EPD': 126, 'spare': 0, 'SecHdr': [1, 2, 3, 4]},
		'Seqn': 0,
	}

	def __init__(self):
		pass

	def isValidEPD(value):
		return True if value == SecurityProtected.mandatoryIEs['5GMMHeaderSec']['EPD'] else False

	def isValidSpare(value):
		return True if value == SecurityProtected.mandatoryIEs['5GMMHeaderSec']['spare'] else False

	def isValidSecHdr(value):
		return True if value in SecurityProtected.mandatoryIEs['5GMMHeaderSec']['SecHdr'] else False
