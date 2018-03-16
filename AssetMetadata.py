'''
This file is used to determine the Metadata of an asset like the type of the operation, allowed_keys to acccess the asset etc.
and these operations are used to communicate with the underlying Blockchain BigchainDB
Created on 13-Nov-2017

@author: sailakshman
'''
from bigchaindb.common import transaction

class Metadata(object):
    '''
    This class represents the data that will be packed in each transaction for PrivAd.
        Attributes:
            : transaction_type 'CREATE' | 'CHANGE' | 'RETRIEVE'
                : CREATE for creating a new data
                : CHANGE for changing the access for a particular data
                : RETRIEVE for retrieving a particular data
            : allowed_keys : a list of public keys that are allowed access to the data
            : data: the actual data to be stored
    :
    '''
    CREATE = 'CREATE'
    CHANGE = 'CHANGE'
    RETRIEVE = 'RETRIEVE'
    TRANSFER= 'TRANSFER'
    TRANSACTION_TYPES = [CREATE, CHANGE, RETRIEVE, TRANSFER]

    def __init__(self, data='', type='CREATE', allowed_keys=[]):
        '''
        TransactionData object can be created by either specifying the values of all the following :
         : transaction_type
         : allowed_keys 
         : data: a dict of user data; the format depends on the user application
        Or by providing a dictionary object which contains these values
        '''
        if isinstance(data,dict):
            self.from_dict(data)
        else:
            self.data = data
            self.transaction_type = type
            self.allowed_keys = allowed_keys
            
    def to_dict(self):
        return { 'type':self.transaction_type,
                 'allowed_keys': self.allowed_keys,
                 'data': self.data,
                 }
    @property
    def transaction_type(self):
        return self.__transaction_type
    
    @transaction_type.setter
    def transaction_type(self, value):
        if value not in self.TRANSACTION_TYPES:
            raise ValueError("transaction type must be one of {}".format(
                                                    ', '.join(self.TRANSACTION_TYPES)))
        self.__transaction_type = value

    def from_dict(self, d):
        if not 'type' in d:
            raise AttributeError("'type' not in the given data")
        if not 'allowed_keys' in d:
            raise AttributeError("'allowed_keys' not in the given data")
        if not 'data' in d:
            raise AttributeError("'data' not in the given data")
        self.transaction_type = d['type']
        self.allowed_keys=d['allowed_keys']
        self.data=d['data']
