import base64
import boto3
from dynamodb_json import json_util as dynamo_json
import json

class Config:
    def get_config(service_region, config_table, partition_key, partition_value):
        dynamo_client = Config.get_client('dynamodb', service_region)
        kms_client = Config.get_client('kms', service_region)

        get_result = dynamo_client.get_item(TableName=config_table, Key={partition_key:{'S':partition_value}})
        config_object = dynamo_json.loads(get_result)
        Config.decrypt_object(kms_client, config_object)

        return config_object['Item']

    def save_config(service_region, config_table, encrypt_key_id, config_data, partition_key, partition_value):
        dynamo_client = Config.get_client('dynamodb', service_region)
        kms_client = Config.get_client('kms', service_region)

        Config.encrypt_object(kms_client, encrypt_key_id, config_data, partition_key, partition_value)
        config_data = dynamo_json.dumps(config_data)
        config_data = json.loads(config_data)
        save_result = dynamo_client.put_item(TableName=config_table, Item=config_data)

        return save_result

    def delete_config(service):
        print("deleting app config")

    def encrypt_object(kms_client, key_id, unencrypted_object, partition_key, partition_value):
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
        for i, list_value in enumerate(unencrypted_list):
            if type(list_value) is dict:
                Config.encrypt_object(kms_client, key_id, unencrypted_list[i], partition_key, partition_value)
            elif type(list_value) is list:
                Config.encrypt_list(kms_client, key_id, list_value, partition_key, partition_value)
            else:
                unencrypted_list[i] = Config.encrypt_text(kms_client, key_id, list_value)

    def decrypt_object(kms_client, encrypted_object):
        for obj_key, obj_value in encrypted_object.items():
            if type(obj_value) is dict:
                Config.decrypt_object(kms_client, obj_value)
            elif type(obj_value) is list:
                Config.decrypt_list(kms_client, obj_value)
            else:
                encrypted_object[obj_key] = Config.decrypt_text(kms_client, obj_value)

    def decrypt_list(kms_client, encrypted_list):
        for i, list_value in enumerate(encrypted_list):
            if type(list_value) is dict:
                Config.decrypt_object(kms_client, encrypted_list[i])
            elif type(list_value) is list:
                Config.decrypt_list(kms_client, encrypted_list[i])
            else:
                encrypted_list[i] = Config.decrypt_text(kms_client, list_value)

    def encrypt_text(kms_client, key_id, string_to_encrypt):
        if type(string_to_encrypt) is int or type(string_to_encrypt) is float:
            string_to_encrypt = str(string_to_encrypt)

        encrypted_value = kms_client.encrypt(KeyId=key_id, Plaintext=string_to_encrypt)
        binary_encrypted = encrypted_value[u'CiphertextBlob']
        encrypted_text = base64.b64encode(binary_encrypted)
        encrypted_utf_string = encrypted_text.decode('utf-8')
        return encrypted_utf_string

    def decrypt_text(kms_client, encrypted_string):
        try:
            decrypted_text = kms_client.decrypt(CiphertextBlob=base64.b64decode(encrypted_string.encode('utf-8')))['Plaintext'].decode('utf-8')
        except:
            return encrypted_string

        return decrypted_text

    def get_client(service_name, service_region):
        this_client = boto3.client(service_name, service_region)

        return this_client