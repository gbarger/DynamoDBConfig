import base64
import boto3
from dynamodb_json import json_util as dynamo_json
import json

class Config:
    def get_config(service_region, config_table, partition_key, partition_value):
        """
            This gets the requested configuration from the DynamoDB configuration table.

            Args:
                service_region (str): The AWS service region: e.g. 'us-east-1'
                config_table (str): The name of the DynamoDB table storing the configurations
                partition_key (str): The name of the partition key for the configuration table
                partition_value (str): The partition value for the config record you want to get

            Returns:
                dict: Returns the umarshalled data from the 'Item' section of the DynamoDB table, 
                      which will include the partition key and value for the record.
        """
        dynamo_client = boto3.client('dynamodb', service_region)
        kms_client = boto3.client('kms', service_region)

        get_result = dynamo_client.get_item(TableName=config_table, Key={partition_key:{'S':partition_value}})
        config_object = dynamo_json.loads(get_result)
        Config.decrypt_object(kms_client, config_object)

        return config_object['Item']

    def save_config(service_region, config_table, encrypt_key_id, config_data, partition_key, partition_value):
        """
            This saves the given configuration data to the requested DynamoDB table after
            enrypting and marshalling for insert to the table. If there is already a 
            configuration there for the provided partition_value, this will overwite the
            existing value.

            Args:
                service_region (str): The AWS service region: e.g. 'us-east-1'
                config_table (str): The name of the DynamoDB table storing the configurations
                encrypt_key_id (str): The Key ID from the IAM Encryption key you are using to 
                                      encrypt the data in the configuration object
                config_data (dict): The object you want to encrypt
                partition_key (str): The name of the partition key for the configuration table
                partition_value (str): The partition value for the config record you want to encrypt

            Returns:
                dict: Returns the DynamoDB save result, which should have an HTTPStatusCode value
                      of 200 if the save was successful.
        """
        dynamo_client = boto3.client('dynamodb', service_region)
        kms_client = boto3.client('kms', service_region)

        Config.encrypt_object(kms_client, encrypt_key_id, config_data, partition_key, partition_value)
        config_data = dynamo_json.dumps(config_data)
        config_data = json.loads(config_data)

        if partition_key not in config_data:
            config_data[partition_key] = {'S':partition_value}

        save_result = dynamo_client.put_item(TableName=config_table, Item=config_data)

        return save_result

    def delete_config(service_region, config_table, partition_key, partition_value):
        """
            Deletes the given configuration record from the DynamoDB configuration table

            Args:
                service_region (str): The AWS service region: e.g. 'us-east-1'
                config_table (str): The name of the DynamoDB table storing the configurations
                partition_key (str): The name of the partition key for the configuration table
                partition_value (str): The partition value for the config record you want to delete

            Returns:
                dict: Returns the DynamoDB delete result, which should have an HTTPStatusCode value
                      of 200 if the delete was successful.
        """
        dynamo_client = boto3.client('dynamodb', service_region)
        delete_result = dynamo_client.delete_item(TableName=config_table, Key={partition_key:{'S':partition_value}})

        return delete_result

    def encrypt_object(kms_client, key_id, unencrypted_object, partition_key, partition_value):
        """
            Encrypts each value in the requsted object. Note that all values should be strings. If 
            you pass any int, float, or bool it will convert those to a string in order to encrypt
            the value, and when it decrypts the objects, those will be strings.

            Args:
                kms_client (boto3.client): This is the kms client that will be used to encrypt the 
                                           object data.
                key_id (str): The Key ID from the IAM Encryption key you are using to 
                              encrypt the data in the configuration object
                unencrypted_object (dict): The object you want encrypted
                partition_key (str): The name of the partition key for the configuration table
                partition_value (str): The partition value for the config record you want to encrypt
        """
        for obj_key, obj_value in unencrypted_object.items():
            # don't encrypt the key
            if obj_key == partition_key and obj_value == partition_value:
                continue
            elif type(obj_value) is dict:
                Config.encrypt_object(kms_client, key_id, obj_value, partition_key, partition_value)
            elif type(obj_value) is list:
                Config.encrypt_list(kms_client, key_id, obj_value, partition_key, partition_value)
            else:
                unencrypted_object[obj_key] = Config.encrypt_text(kms_client, key_id, obj_value)

    def encrypt_list(kms_client, key_id, unencrypted_list, partition_key, partition_value):
        """
            Encrypts each value in the requsted list. This is a helper for the encrypt_object method
            when it encounters a list. If this encounters child objects, those will be sent to the
            encrypt_object method.

            Args:
                kms_client (boto3.client): This is the kms client that will be used to encrypt the 
                                           object data.
                key_id (str): The Key ID from the IAM Encryption key you are using to 
                              encrypt the data in the configuration object
                unencrypted_list (list): The list you want encrypted
                partition_key (str): The name of the partition key for the configuration table
                partition_value (str): The partition value for the config record you want to encrypt
        """
        for i, list_value in enumerate(unencrypted_list):
            if type(list_value) is dict:
                Config.encrypt_object(kms_client, key_id, unencrypted_list[i], partition_key, partition_value)
            elif type(list_value) is list:
                Config.encrypt_list(kms_client, key_id, list_value, partition_key, partition_value)
            else:
                unencrypted_list[i] = Config.encrypt_text(kms_client, key_id, list_value)

    def decrypt_object(kms_client, encrypted_object):
        """
            Decrypts each value in the requsted object. Note that all values returned will be strings.

            Args:
                kms_client (boto3.client): This is the kms client that will be used to decrypt the 
                                           object data.
                encrypted_object (dict): The object you want decrypted
        """
        for obj_key, obj_value in encrypted_object.items():
            if type(obj_value) is dict:
                Config.decrypt_object(kms_client, obj_value)
            elif type(obj_value) is list:
                Config.decrypt_list(kms_client, obj_value)
            else:
                encrypted_object[obj_key] = Config.decrypt_text(kms_client, obj_value)

    def decrypt_list(kms_client, encrypted_list):
        """
            Decrypts each value in the requsted list. This is a helper for the decrypt_object method
            when it encounters a list. If this encounters child objects, those will be sent to the
            decrypt_object method.

            Args:
                kms_client (boto3.client): This is the kms client that will be used to decrypt the 
                                           object data.
                encrypted_list (list): The list you want decrypted
        """
        for i, list_value in enumerate(encrypted_list):
            if type(list_value) is dict:
                Config.decrypt_object(kms_client, encrypted_list[i])
            elif type(list_value) is list:
                Config.decrypt_list(kms_client, encrypted_list[i])
            else:
                encrypted_list[i] = Config.decrypt_text(kms_client, list_value)

    def encrypt_text(kms_client, key_id, string_to_encrypt):
        """
            This method encrypts the provided value

            Args:
                kms_client (boto3.client): This is the kms client that will be used to encrypt the 
                                           object data.
                key_id (str): The Key ID from the IAM Encryption key you are using to 
                              encrypt the data in the configuration object
                string_to_encrypt (str): The string you want encrypted. If this is an int, float, 
                                         or bool, it will be converted to a string.

            Returns:
                str: The encrypted value of the input string. If there is an error in the 
                     encryption process, this will return the original value.
        """
        try:
            if type(string_to_encrypt) is int or type(string_to_encrypt) is float or type(string_to_encrypt) is bool:
                string_to_encrypt = str(string_to_encrypt)

            encrypted_value = kms_client.encrypt(KeyId=key_id, Plaintext=string_to_encrypt)
            binary_encrypted = encrypted_value[u'CiphertextBlob']
            encrypted_text = base64.b64encode(binary_encrypted)
            encrypted_utf_string = encrypted_text.decode('utf-8')
            return encrypted_utf_string
        except:
            return string_to_encrypt

    def decrypt_text(kms_client, encrypted_string):
        """
            This method decrypts the provided string. If there is a decrypt error, this will 
            return the input string.

            Args:
                kms_client (boto3.client): This is the kms client that will be used to decrypt the 
                                           object data.
                encrypted_string (str): This is the string that will be decrypted

            Returns:
                str: The decrypted value of the input string.
        """
        try:
            decrypted_text = kms_client.decrypt(CiphertextBlob=base64.b64decode(encrypted_string.encode('utf-8')))['Plaintext'].decode('utf-8')
            return decrypted_text
        except:
            return encrypted_string