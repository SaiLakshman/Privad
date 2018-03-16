'''
This file consists of all the exceptions related to the user login in PrivAd Wallet 
Created on 13-Nov-2017

@author: sailakshman
'''

class IncorrectPasswordError(ValueError):
    '''To prompt Incorrect Password Error'''
class UnregisteredUserError(ValueError):
    '''To prompt Unregistered User Error'''
class UserAlreadyExistsError(ValueError):
    '''To prompt UserAlready Exists Error'''
