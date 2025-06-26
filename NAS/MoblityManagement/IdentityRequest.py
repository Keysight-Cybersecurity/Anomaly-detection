from pycrate_mobile.NAS5G import *


class IdentityRequest:
	mandatoryIEs = {
		'5GMMHeader': {'EPD': 126, 'spare': 0, 'SecHdr': 0, 'Type': 91},
		'spare': 0,
		'5GSID': 0,
	}

	def __init__(self):
		pass

	def isValidEPD(value):
		return True if value == IdentityRequest.mandatoryIEs['5GMMHeader']['EPD'] else False

	def isValidSpare(value):
		return True if value == IdentityRequest.mandatoryIEs['5GMMHeader']['spare'] else False

	def isValidSecHdr(value):
		return True if value == IdentityRequest.mandatoryIEs['5GMMHeader']['SecHdr'] else False

	def isValidSpareBody(value):
		return True if value == IdentityRequest.mandatoryIEs['spare'] else False

	def isValid5GSID(value):
		return True
