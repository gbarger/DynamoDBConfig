import base64
import json

import boto3

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

        encrypted_string = get_result.get('Item', {}).get('encrypted_data', {}).get('S', '')
        decrypted_string = kms_client.decrypt(CiphertextBlob=base64.b64decode(encrypted_string.encode('utf-8')))['Plaintext'].decode('utf-8')

        config_data = json.loads(decrypted_string)

        return config_data

    def get_config_format(service_region, config_table, partition_key, partition_value):
        """
        This gets the configuration example.

        Args:
            service_region (str): The AWS service region: e.g. 'us-east-1'
            config_table (str): The name of the DynamoDB table storing the configurations
            partition_key (str): The name of the partition key for the configuration table
            partition_value (str): The partition value for the config record you want to get

        Returns:
            dict: Returns an example of what data is stored in the encrypted configuration.
        """
        dynamo_client = boto3.client('dynamodb', service_region)
        get_result = dynamo_client.get_item(TableName=config_table, Key={partition_key:{'S':partition_value}})
        format_object_string = get_result.get('Item', {}).get('object_format', {}).get('S', '')

        formatted_object = json.loads(format_object_string)

        return formatted_object

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

        config_string = json.dumps(config_data)
        encrypted_string = kms_client.encrypt(KeyId=encrypt_key_id, Plaintext=config_string)
        binary_encrypted = encrypted_string[u'CiphertextBlob']
        encrypted_text = base64.b64encode(binary_encrypted)
        encrypted_utf_string = encrypted_text.decode('utf-8')

        Config.format_object(config_data)
        formatted_object_string = json.dumps(config_data)

        save_object = {}
        save_object[partition_key] = {'S':partition_value}
        save_object['encrypted_data'] = {'S':encrypted_utf_string}
        save_object['object_format'] = {'S':formatted_object_string}

        save_result = dynamo_client.put_item(TableName=config_table, Item=save_object)
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

    def format_object(the_object):
        """
        this replaces all values in the object with the object type. The purpose for
        this is just to allow you to see what type of data was stored in the object 
        in case the key is wiped out and you can't retrieve the object any more.

        Args:
            the_object (dict): The object you want to convert to an example
        """
        for obj_key, obj_value in the_object.items():
            if type(obj_value) is dict:
                Config.format_object(obj_value)
            elif type(obj_value) is list:
                Config.format_list(obj_value)
            else:
                the_object[obj_key] = str(type(obj_value))

    def format_list(the_list):
        """
        This replaces all values in the list with the with the list type. The 
        purpose for this is to allow you to see what type of data was stored
        in the list in case the key is wiped out and you can't retrieve the 
        list any more.

        Args:
            the_list (list): The list you want to convert to an example.
        """
        for i, list_value in enumerate(the_list):
            if type(list_value) is dict:
                Config.format_object(list_value)
            elif type(list_value) is list:
                Config.format_list(list_value)
            else:
                the_list[i] = str(type(list_value))