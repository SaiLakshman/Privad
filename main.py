from user import User
from wallet import Wallet
import crypto_utils
import bigchaindb_driver
import json 
import getpass
import random
from exceptions import IncorrectPasswordError, UnregisteredUserError, UserAlreadyExistsError
from bigchaindb.common.transaction import TransactionLink
from crypto_utils import decrypt, generate_key_from_password

DATAFILE = '/home/sailakshman/Desktop/MedRec/walletwithchanges/patients_data.dat'

if __name__ == '__main__':
   u= User()
   w= Wallet()
   var = 1
   f = open(DATAFILE, 'r')
   patient_data = json.load(f)
   print("Welcome to PrivAd\n")
   print("----------------------------------------------------\n")
   signIn= input("LOGIN or REGISTER: ")
   if signIn.lower() == "login":
      username= input("Username: ")
      password= getpass.getpass("Password: ")
      u=w.fetch_user(username,password)
   elif signIn.lower() == "register":
      u.get_input()
      w.add_user(u)
   print("----------------------------------------------------\n")
   while var == 1:
      print("####################################################\n")
      typeofOp= input("Enter the type of Operation: \n1.Create\n2.Retrieve\n3.Share\n4.Modify\n5.Display Assets\n6.Userdata\n7.Asset Details\n\n")   
      if typeofOp.lower() == "create":
         asset_id= u.create_asset(patient_data[1])
         print(" Creation Successful \n")
         print("Asset Id: ",asset_id)
          
      if typeofOp.lower() == "retrieve":
         asset_id= input("Enter ID of the asset to be Retreived: \n")
         hello= u.retrieve_txn(asset_id) 
         allowed_keys= hello['metadata']['allowed_keys']
         if not u.public_key in allowed_keys:
            print("Permission Denied.")
         else:
            print(u.retrieve_asset(asset_id))
    
      if typeofOp.lower() == "share":
         asset_id= input("Enter ID of the asset to be Shared: \n")
         hello= u.retrieve_txn(asset_id) 
         allowed_keys= hello['metadata']['allowed_keys']
         if not u.public_key in allowed_keys:
            print("Update Failed. Permission Denied.")
         else:
            updated_user= input("Share with : ")
            if not updated_user in Wallet._users:
               raise UnregisteredUserError(updated_user + ' is not a registered user')
               sys.exit()
            pk_updated_user= w.get_public_key(updated_user)
            share_pubkey= w.get_share_pubkey(updated_user)
            u_asset_id= u.update_allowed_keys_asset(asset_id, allowed_keys,pk_updated_user,share_pubkey)
            print("Updation Successful ",u_asset_id)
      
      if typeofOp.lower() == "modify":
         asset_id= input("Enter ID of the asset to be modified: \n")
         hello= u.retrieve_txn(asset_id) 
         allowed_keys= hello['metadata']['allowed_keys']
         if not u.public_key in allowed_keys:
            print("Permission Denied.Can't Modify the data.")
         else:
            modified_asset_id= u.modify_asset(asset_id,u.public_key)
            print("Modification Successful.", modified_asset_id)
            
      if typeofOp.lower() == "transfer":
         asset_id= input("Enter ID of the asset to be Transferred: \n")
         hello= u.retrieve_txn(asset_id)
         allowed_keys= hello['metadata']['allowed_keys']
         if not u.public_key in allowed_keys:
            print("Transfer Failed. Permission Denied.")
         else:
            new_owner= input("Transfer to: ")
            if not new_owner in Wallet._users:
               raise UnregisteredUserError(new_owner + 'is not a registered user')
               sys.exit()
            pk_new_owner= w.get_public_key(new_owner)
            trans_asset_id= u.transfer_asset(asset_id,pk_new_owner)
            print(trans_asset_id)

      if typeofOp.lower() == "display assets":
         print(u.display_all_assets())
#         for i in u.get_owned_ids():
#            print(i.txid)
      
      if typeofOp.lower() == "userdata":
         print('Username: ', u.username)
         print('Public Key: ', u.public_key)
      if typeofOp.lower() == "asset details":
         asset_id= input("Enter ID of the asset: \n")
         w.get_asset_details(asset_id)
         w.get_username_given_public_key(u.public_key)
     
      if typeofOp.lower()=="try":
         generate_shared_secret("alice","bob")
         
      print("####################################################\n")


#if __name__ == '__main__':
   #username= input("Enter the username: ")
   #password= input("Enter the password: ")
#   u= User()
#   w= Wallet()
#for adding new user into PrivAd
   #u.get_input()
   #print(u.to_dict())
   #w.add_user(u)
   #u= w.user_login()
   #u.set_with_username_password()  
#   print("Logging in !!!!")
   #u= w.fetch_user('sailakshman','ihatepasswords')
   #u= w.fetch_user('lucky','sairam')

#for getting the records of the patients and creating the assets in BigchainDB
   #f = open(DATAFILE, 'r')
   #patient_data = json.load(f)
   #print(patient_data)
   #print(patient_data[0])
   #asset_id= u.create_asset(patient_data[1])

# for knowing what all assets are owned by a user
   #print("Assets owned by ", u)
   #print(u.display_all_assets())

# retriving assets on the basis of transaction_id
# b5f8b6e78b21fc08d898fe18559fb2a6035880a4373e223af34a3609be1e738d of user lucky
# 904c99edfc76f8eeab0f392caf6aa13c137a59ec8bc0535c58be4314a5541178 of transfer transaction
#   for txn in u.get_all_txns():
#       hello= u.retrieve_txn(txn['id']) 
#       print(hello['id'])
#   print('\n')
   #for ids in u.get_owned_ids():
       #print(ids.to_dict())
# for getting all the allowed_keys for the asset used for update
#   allowed_keys= hello['metadata']['allowed_keys']
#   print(allowed_keys)
#   asset_id= 'b5f8b6e78b21fc08d898fe18559fb2a6035880a4373e223af34a3609be1e738d'
#   u.update_access(asset_id, allowed_keys)
#   print("User Info: \n") 
#   print(u)
# for retrieving assets based on their id
       #print(u.retrieve_asset(hello['id']))
   

#for deleting the user in the blockchain
   #w.del_user('lucky')
