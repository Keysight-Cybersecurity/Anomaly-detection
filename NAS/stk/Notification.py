class Notification:
	mandatoryIEs = {
		'5GMMHeader': {'EPD': 126, 'spare': 0, 'SecHdr': 0, 'Type': 101},
		'spare': 0,
		'AccessType': 0,
	}

	def __init__(self):
		pass

	def isValidEPD(value):
		return True if value == Notification.mandatoryIEs['5GMMHeader']['EPD'] else False

	def isValidSpare(value):
		return True if value == Notification.mandatoryIEs['5GMMHeader']['spare'] else False

	def isValidSecHdr(value):
		return True if value == Notification.mandatoryIEs['5GMMHeader']['SecHdr'] else False

	def isValidSpareBody(value):
		return True if value == Notification.mandatoryIEs['spare'] else False

	def isValidAccessType(value):
		return True
