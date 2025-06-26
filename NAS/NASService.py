from binascii import unhexlify
from pycrate_mobile.NAS5G import *
from pycrate_core.elt import Element
import logging
import pyshark
import pandas as pd
import copy
import os.path as path
from .MoblityManagement import *


class NASService:
	protocol = 'nas-5gs and not http and not http2 and not http3 and not json'
	validNasNumbers = {
			65: 'RegistrationRequest',
			66: 'RegistrationAccept',
			67: 'RegistrationComplete',
			68: 'RegistrationReject',

			69: 'DeregistrationRequestUE',
			70: 'DeregistrationAcceptUE',
			71: 'DeregistrationRequestAMF',
			72: 'DeregistrationAcceptAMF',

			76: 'ServiceRequest',
			77: 'ServiceReject',
			78: 'ServiceAccept',

			79: 'ControlPlaneServiceRequest',

			80: 'NetworkSliceSpecificAuthenticationCommand',
			81: 'NetworkSliceSpecificAuthenticationComplete',
			82: 'NetworkSliceSpecificAuthenticationResult',

			84: 'ConfigurationUpdateCommand',
			85: 'ConfigurationUpdateComplete',

			86: 'AuthenticationRequest',
			87: 'AuthenticationResponse',
			88: 'AuthenticationReject',
			89: 'AuthenticationFailure',
			90: 'AuthenticationResult',

			91: 'IdentityRequest',
			92: 'IdentityResponse',
			93: 'SecurityModeCommand',
			94: 'SecurityModeComplete',
			95: 'SecurityModeReject',
			00: 'SecurityProtected',

			100: 'Status',

			101: 'Notification',
			102: 'NotificationResponse',

			103: 'ULNASTransport',
			104: 'DLNASTransport',


			# 1: 'RelayRequest',
			# 1: 'RelayAccept',
			# 1: 'RelayReject',
			#
			# 1: 'RelayAuthenticationRequest',
			# 1: 'RelayAuthenticationResponse',
	}

	allTypes = [value for value in validNasNumbers.values()]

	amfMessageTypes = [66, 68, 71, 72, 77, 78, 80, 82, 84, 86, 88, 90, 91, 93, 100, 101, 104, ]
	ueMessageTypes = [65, 67, 69, 70, 76, 79, 81, 85, 87, 89, 92, 94, 95, 100, 102, 103, ]

	sibling = {

		'RegistrationRequest': ['None', 'DeregistrationAcceptAMF', 'DeregistrationAcceptUE', 'AuthenticationFailure', 'ULNASTransport'],
		'RegistrationAccept': ['SecurityModeComplete'],
		'RegistrationComplete': ['RegistrationAccept'],
		'RegistrationReject': [], #todo

		'DeregistrationRequestAMF': allTypes,
		'DeregistrationRequestUE': allTypes,
		'DeregistrationAcceptAMF': ['DeregistrationRequestUE'],
		'DeregistrationAcceptUE': ['DeregistrationRequestAMF', 'DeregistrationRequestUE'],

		'ServiceRequest': ['ServiceAccept', 'ULNASTransport'], #todo
		'ServiceAccept': ['ServiceRequest'],
		'ServiceReject': ['ServiceRequest'],

		'AuthenticationRequest': ['RegistrationRequest', 'AuthenticationFailure', 'DeregistrationRequestUE',
								  'DeregistrationRequestAMF', 'ULNASTransport'],
		'AuthenticationResponse': ['AuthenticationRequest'],
		'AuthenticationResult': ['AuthenticationResponse'],
		'AuthenticationReject': ['AuthenticationResponse', ],
		'AuthenticationFailure': ['AuthenticationRequest'],

		'SecurityModeCommand': ['AuthenticationResponse', 'AuthenticationResult', ''],
		'SecurityModeComplete': ['SecurityModeCommand'],
		'SecurityModeReject': ['SecurityModeCommand'],

		'ULNASTransport': ['DLNASTransport', 'RegistrationComplete', 'ULNASTransport'],
		'DLNASTransport': ['SecurityModeComplete', 'ULNASTransport'],

		'ConfigurationUpdateCommand': [],
		'ConfigurationUpdateComplete': [],
		'ControlPlaneServiceRequest': ['RelayRequest'],

		'IdentityRequest': ['RegistrationRequest', 'ServiceRequest'],
		'IdentityResponse': ['IdentityRequest'],

		'NetworkSliceSpecificAuthenticationCommand': [],
		'NetworkSliceSpecificAuthenticationComplete': [],
		'NetworkSliceSpecificAuthenticationResult': [],

		'Notification': [],
		'NotificationResponse': [],

		'RelayRequest': [],
		'RelayAccept': [],
		'RelayReject': [],

		'RelayAuthenticationRequest': [],
		'RelayAuthenticationResponse': [],

		'Status': []
	}


	def __init__(self):
		pass

	def isValidType(self, row):
		try:
			className = self.validNasNumbers[int(row['Type'])]
			return True
		except (KeyError, ValueError) as e:
			return False

	def hasValidSecrFlow(self, row):
		if not row['valid_Type']:
			return -1
		if not row['valid_SecHdr']:
			return -1

		global secMode
		secMode = False if 'secMode' not in globals() else secMode

		if secMode is False and int(row['SecHdr']) == 0:
			return True
		elif secMode is False and int(row['SecHdr']) > 0 and str(row['Type']) != '-1' and int(row['Type']) == 93:
			secMode = True
			return True
		elif secMode is True and int(row['SecHdr']) > 0:
			return True
		else:
			print('Invalid security flow detected')
			return False

	def hasValidMinAuthFailureRate(self, row, df):
		if not row['valid_Type']:
			return -1

		count = 0
		for i, r in df.iterrows():
			if int(r['Type']) == 89:
				count += 1

		if int(row['Type']) == 89 and count >= 3:
			return False
		elif int(row['Type']) == 89 and count < 3:
			return True
		return -1

	def hasValidMessageFlow(self, row):
		result = False
		if not row['valid_Type']:
			return -1

		currentType = int(row['Type'])
		currentPDUName = self.validNasNumbers.get(currentType)

		global previousType
		previousType = [] if 'previousType' not in globals() else previousType

		previousPDUName = self.validNasNumbers.get(int(previousType[-1])) if len(previousType) > 0 else 'None'

		if self.sibling.get(currentPDUName) is None:
			# result = 'NoRelationship'
			result = -2
		elif previousPDUName in self.sibling.get(currentPDUName):
			result = True
		else:
			result = False

		if result is False or result == -1:
			pr = "" if previousType[-1] is None else str(previousType[-1])
			print(f"Invalid order detected: Previous {pr} | Next {str(row['Type'])}")

		previousType.append(copy.deepcopy(currentType))
		return result


	def isValidSecHdr(self, row):
		if row['valid_Type'] is not True:
			return -1

		sechdr = -1
		try:
			sechdr = int(row['SecHdr'])
		except (KeyError, ValueError) as e:
			print('Invalid security header detected')
			return False

		if sechdr > 0:
			className = 'SecurityProtected'

			if sechdr == 3 and int(row['Type']) != 93:
				print('Invalid security header detected')
				return False

			if sechdr == 4 and int(row['Type']) != 94:
				print('Invalid security header detected')
				return False
		else:
			className = self.validNasNumbers[int(row['Type'])]

		MessageClass = getattr(globals()[className], className)
		result = MessageClass.isValidSecHdr(sechdr)
		if result is False:
			print('Invalid security header detected')
		return result

	def isValidEPD(self, row):
		if row['valid_Type'] is not True:
			return -1

		if row['valid_SecHdr'] is not True:
			return -1

		sechdr = int(row['SecHdr'])
		if sechdr > 0:
			className = 'SecurityProtected'
		else:
			className = self.validNasNumbers[int(row['Type'])]

		MessageClass = getattr(globals()[className], className)
		try:
			result = MessageClass.isValidEPD(int(row['EPD']))
		except (KeyError, ValueError) as e:
			result = False

		if result is False:
			print('Invalid EPD detected')

		return result

	def isValidSpare(self, row):
		if row['valid_Type'] is not True:
			return -1

		if row['valid_SecHdr'] is not True:
			return -1

		sechdr = int(row['SecHdr'])
		if sechdr > 0:
			className = 'SecurityProtected'
		else:
			className = self.validNasNumbers[int(row['Type'])]

		MessageClass = getattr(globals()[className], className)
		try:
			result = MessageClass.isValidSpare(int(row['spare']))
		except (KeyError, ValueError) as e:
			result = False

		if result is False:
			print('Invalid spare detected')
		return result

	
	




	def isValidSeqn(self, row):
		if row['valid_Type'] is not True:
			return -1
		if row['valid_SecHdr'] is not True:
			return -1

		if int(row['SecHdr']) == 0:
			return -1

		currentSeqnNo = -1
		try:
			currentSeqnNo = int(row['Seqn'])
		except (KeyError, ValueError) as e:
			pass

		global previousUESeqnNo
		previousUESeqnNo = [-1] if 'previousUESeqnNo' not in globals() else previousUESeqnNo

		global previousAMFSeqnNo
		previousAMFSeqnNo = [-1] if 'previousAMFSeqnNo' not in globals() else previousAMFSeqnNo

		if int(row['Type']) in self.amfMessageTypes:
			if currentSeqnNo == previousAMFSeqnNo[-1] + 1:
				previousAMFSeqnNo.append(copy.deepcopy(currentSeqnNo))
				result = True
			else:
				result = False
		elif int(row['Type']) in self.ueMessageTypes:
			if currentSeqnNo == previousUESeqnNo[-1] + 1:
				previousUESeqnNo.append(copy.deepcopy(currentSeqnNo))
				result = True
			else:
				result = False
		else:
			result = -1

		if result is False:
			print('Invalid sequence number detected')
		return result

	def isValid5GSID(self, row):
		if row['valid_Type'] is not True:
			return -1
		className = self.validNasNumbers[int(row['Type'])]

		value = -1
		MessageClass = None
		try:
			value = int(row['5GSID'])
			if value == -1:
				return -1
		except (KeyError, ValueError) as e:
			pass

		try:
			MessageClass = getattr(globals()[className], className)
			result = MessageClass.isValid5GSID(value)
		except AttributeError:
			result = -1 if value == -1 else False

		if result is False:
			print('Invalid 5GSID detected')
		return result

	def isValidPayloadContainer(self, row):
		if row['valid_Type'] is not True:
			return -1
		className = self.validNasNumbers[int(row['Type'])]

		value = -1
		MessageClass = None
		try:
			value = int(row['PayloadContainer'])
		except (KeyError, ValueError) as e:
			pass

		try:
			MessageClass = getattr(globals()[className], className)
			result = MessageClass.isValidPayloadContainer(value)
		except AttributeError:
			result = -1 if value == -1 else False

		if result is False:
			print('Invalid payload container detected')
		return result


	def isValidNASKSI(self, row):
		if row['valid_Type'] is not True:
			return -1
		className = self.validNasNumbers[int(row['Type'])]

		value = -1
		MessageClass = None
		try:
			value = int(row['NAS_KSI'])
		except (KeyError, ValueError) as e:
			pass

		try:
			MessageClass = getattr(globals()[className], className)
			result = MessageClass.isValidNASKSI(value)
		except AttributeError:
			result = -1 if value == -1 else False

		if result is False:
			print('Invalid NAS_KSI detected')
		return result

	def isValid5GSRegType(self, row):
		if row['valid_Type'] is not True:
			return -1
		className = self.validNasNumbers[int(row['Type'])]

		value = -1
		MessageClass = None
		try:
			value = int(row['5GSRegType'])
		except (KeyError, ValueError) as e:
			pass

		try:
			MessageClass = getattr(globals()[className], className)
			result = MessageClass.isValid5GSRegType(value)
		except AttributeError:
			result = -1 if value == -1 else False

		if result is False:
			print('Invalid 5GSRegType detected')
		return result

	def isValidPayloadContainerType(self, row):
		if row['valid_Type'] is not True:
			return -1
		className = self.validNasNumbers[int(row['Type'])]

		value = -1
		MessageClass = None
		try:
			value = int(row['PayloadContainerType'])
		except (KeyError, ValueError) as e:
			pass

		try:
			MessageClass = getattr(globals()[className], className)
			result = MessageClass.isValidPayloadContainerType(value)
		except AttributeError:
			result = -1 if value == -1 else False

		if result is False:
			print('Invalid payload container type detected')
		return result

	def isValidServiceType(self, row):
		if row['valid_Type'] is not True:
			return -1
		className = self.validNasNumbers[int(row['Type'])]

		value = -1
		MessageClass = None
		try:
			value = int(row['ServiceType'])
		except (KeyError, ValueError) as e:
			pass

		try:
			MessageClass = getattr(globals()[className], className)
			result = MessageClass.isValidServiceType(value)
		except AttributeError:
			result = -1 if value == -1 else False

		if result is False:
			print('Invalid service type detected')
		return result

	def isValidDeregistrationType(self, row):
		if row['valid_Type'] is not True:
			return -1
		className = self.validNasNumbers[int(row['Type'])]

		value = -1
		MessageClass = None
		try:
			value = int(row['DeregistrationType'])
		except (KeyError, ValueError) as e:
			pass

		try:
			MessageClass = getattr(globals()[className], className)
			result = MessageClass.isValidDeregistrationType(value)
		except AttributeError:
			result = -1 if value == -1 else False

		if result is False:
			print('Invalid Deregistration type detected')
		return result


	def isValidCause(self, row):
		if row['valid_Type'] is not True:
			return -1
		className = self.validNasNumbers[int(row['Type'])]

		value = -1
		MessageClass = None
		try:
			value = int(row['5GMMCause'])
		except (KeyError, ValueError) as e:
			pass

		try:
			MessageClass = getattr(globals()[className], className)
			result = MessageClass.isValidCause(value)
		except AttributeError:
			result = -1 if value == -1 else False

		if result is False:
			print('Invalid 5GMM Cause detected')
		return result

	def isValidPRTI(self, row):
		if row['valid_Type'] is not True:
			return -1
		className = self.validNasNumbers[int(row['Type'])]

		value = -1
		MessageClass = None
		try:
			value = int(row['PRTI'])
		except (KeyError, ValueError) as e:
			pass

		try:
			MessageClass = getattr(globals()[className], className)
			result = MessageClass.isValidPRTI(value)
		except AttributeError:
			result = -1 if value == -1 else False

		if result is False:
			print('Invalid PRTI detected')
		return result

	def isValidEAP(self, row):
		if row['valid_Type'] is not True:
			return -1
		className = self.validNasNumbers[int(row['Type'])]

		value = -1
		MessageClass = None
		try:
			value = int(row['EAPmsg'])
		except (KeyError, ValueError) as e:
			pass

		try:
			MessageClass = getattr(globals()[className], className)
			result = MessageClass.isValidEAP(value)
		except AttributeError:
			result = -1 if value == -1 else False

		if result is False:
			print('Invalid EAPmsg detected')
		return result

	def isValidNSSAI(self, row):
		if row['valid_Type'] is not True:
			return -1
		className = self.validNasNumbers[int(row['Type'])]

		value = -1
		MessageClass = None
		try:
			value = int(row['NSSAI'])
		except (KeyError, ValueError) as e:
			pass

		try:
			MessageClass = getattr(globals()[className], className)
			result = MessageClass.isValidNSSAI(value)
		except AttributeError:
			result = -1 if value == -1 else False

		if result is False:
			print('Invalid NSSAI detected')
		return result

	def isValidRequestParameters(self, row):
		if row['valid_Type'] is not True:
			return -1
		className = self.validNasNumbers[int(row['Type'])]

		value = -1
		MessageClass = None
		try:
			value = int(row['RequestParameters'])
		except (KeyError, ValueError) as e:
			pass

		try:
			MessageClass = getattr(globals()[className], className)
			result = MessageClass.isValidRequestParameters(value)
		except AttributeError:
			result = -1 if value == -1 else False

		if result is False:
			print('Invalid Request parameters detected')
		return result



	def isValidABBA(self, row):
		if row['valid_Type'] is not True:
			return -1
		className = self.validNasNumbers[int(row['Type'])]

		value = -1
		MessageClass = None
		try:
			value = int(row['ABBA'])
		except (KeyError, ValueError) as e:
			pass

		try:
			MessageClass = getattr(globals()[className], className)
			result = MessageClass.isValidABBA(value)
		except AttributeError:
			result = -1 if value == -1 else False

		if result is False:
			print('Invalid ABBA detected')
		return result

	def isValidUESecCap(self, row):
		if row['valid_Type'] is not True:
			return -1
		className = self.validNasNumbers[int(row['Type'])]

		value = -1
		MessageClass = None
		try:
			value = int(row['UESecCap'])
		except (KeyError, ValueError) as e:
			pass

		try:
			MessageClass = getattr(globals()[className], className)
			result = MessageClass.isValidUESecCap(value)
		except AttributeError:
			result = -1 if value == -1 else False

		if result is False:
			print('Invalid UESecCap detected')
		return result

	def isValidNASSecAlgo(self, row):
		if row['valid_Type'] is not True:
			return -1
		className = self.validNasNumbers[int(row['Type'])]

		value = -1
		MessageClass = None
		try:
			value = int(row['NASSecAlgo'])
		except (KeyError, ValueError) as e:
			pass

		try:
			MessageClass = getattr(globals()[className], className)
			result = MessageClass.isValidNASSecAlgo(value)
		except AttributeError:
			result = -1 if value == -1 else False

		if result is False:
			print('Invalid NASSecAlgo detected')
		return result

	def isValidAccessType(self, row):
		if row['valid_Type'] is not True:
			return -1
		className = self.validNasNumbers[int(row['Type'])]

		value = -1
		MessageClass = None
		try:
			value = int(row['AccessType'])
		except (KeyError, ValueError) as e:
			pass

		try:
			MessageClass = getattr(globals()[className], className)
			result = MessageClass.isValidAccessType(value)
		except AttributeError:
			result = -1 if value == -1 else False

		if result is False:
			print('Invalid Access type detected')
		return result

	def isValidResponseParameters(self, row):
		if row['valid_Type'] is not True:
			return -1
		className = self.validNasNumbers[int(row['Type'])]

		value = -1
		MessageClass = None
		try:
			value = int(row['ResponseParameters'])
		except (KeyError, ValueError) as e:
			pass

		try:
			MessageClass = getattr(globals()[className], className)
			result = MessageClass.isValidResponseParameters(value)
		except AttributeError:
			result = -1 if value == -1 else False

		if result is False:
			print('Invalid Response parameters detected')
		return result


	def label(self, row):
		result = []
		for key in list(row.keys()):
			if 'valid_' in key:
				if int(row[key]) == -1:
					continue
				else:
					result.append(row[key])

		return all(result)
