'''
This file is of the wallet realted stuff 
Created on 13-Nov-2017

@author: sailakshman
'''

import json
import getpass
from user import User
from exceptions import IncorrectPasswordError, UnregisteredUserError,UserAlreadyExistsError
class Wallet(object):
    _users = None
    _USER_FILENAME= '/home/sailakshman/Desktop/MedRec/walletwithchanges/users.txt'   
    @property
    def users(self):
        if not self._users:
            self.__retrieve_users()
        return self._users
        
    @classmethod
    def __store_users(cls):
        try: 
            user_file = open(cls._USER_FILENAME, 'w') 
        except FileNotFoundError:
            user_file = open(cls._USER_FILENAME,  'x')
        json.dump(cls._users, user_file)
        user_file.close()
        
    @classmethod
    def __retrieve_users(cls):
        try:
            user_file = open(cls._USER_FILENAME, 'r')
            cls._users = json.load(user_file) or {}
            user_file.close()
        except FileNotFoundError:
            print('file not found')
            cls._users = {}
    
#     def __del__(self):
#         self.__store_users()
        
    def __init__(self):
        self.__retrieve_users()
             
    def user_exists(self, username):
        return username in self.users
    
    
    def add_user(self, user):
        '''
        Add a given user of the User class to the list of users in the system
        '''
        if not isinstance(user, User):
            raise ValueError('expected a User class object for adding users')
        if user.username in self.users:
            raise UserAlreadyExistsError('user: ' + user.username + ' already exists')
        self._users[user.username] = user.to_dict()
        #TODO: work out a cheaper way to achieve the same
        self.__store_users()
        
    def del_user(self, username):
        if isinstance(username, User):
            username = username.username
        if username not in self.users:
            raise ValueError('user: ' + username + ' does not exist')
        del self.users[username]
        
    def user_login(self):
        username = input('Enter the username: ')
        password = getpass.getpass('Enter the password: ')
        return self.fetch_user(username, password)
    
    def get_public_key(self,user):
        if user not in self.users:
           raise UnregisteredUserError(username + ' is not a registered user')
        details= self.users[user]
        return details['public_key']
   
    def get_share_pubkey(self,user):
        if user not in self.users:
           raise UnregisteredUserError(username + ' is not a registered user')
        details= self.users[user]
        return details['share_pubkey']

    def get_username_given_public_key(self,pub_key):
        for user in self.users:
            details= self.users[user]
            if pub_key == details['public_key']:
               return details['username']
    
    def get_asset_details(self,asset_id):
        u= User()
        txn= u.retrieve_txn(asset_id)
        owners_before= txn['inputs'][0]['owners_before']
        allowed_keys=  txn['metadata']['allowed_keys']
        if len(allowed_keys) == 1:
           print("Current Owner of the Asset: ",self.get_username_given_public_key(allowed_keys[0]))
        for own in owners_before:
           print("Previous owner of the Asset: ",self.get_username_given_public_key(own))
        if len(allowed_keys) > 1:
           for own in allowed_keys:
              print("Asset is being shared with: ",self.get_username_given_public_key(own))


    def fetch_user(self, username, passwd):
        if username not in self.users: 
           raise UnregisteredUserError(username + ' is not a registered user')
        user = User()
        user.from_dict(self.users[username])
        user._check_password(passwd)
        return user
    
    def get_user_details(self,usr):
        details= self.users[usr.username]

if __name__ =='__main__':
   u= User()
   u1= User()
   w= Wallet()
   u.set_with_username_password("hello","sairam")
   u1.set_with_username_password("ello","sairam")
   w.add_user(u)
   w.add_user(u1)
   key1= u.generate_shared_secret(u,u1)
   key2= u.generate_shared_secret(u1,u)
   if key1 == key2:
     print("Swami")
   else:
     print("lakshman")
