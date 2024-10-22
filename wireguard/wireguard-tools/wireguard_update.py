import boto3
import json
import sys
import time
import requests
import argparse
from botocore.exceptions import NoCredentialsError, PartialCredentialsError

def getAWSCreds(role_arn, role_to_assume_from = None):
	# Cloudformation calls require an elevated iam role to perform its functions
	# Because of this, we have created an admin role that can be only be assumed from the 
	# AWS Role configured in the production account, as its more secure.
	# The code has been refactored to reflect this, and assume the role from the allowed role.
	from datetime import datetime
	current_datetime = datetime.now()
	session_date = current_datetime.strftime('%Y%m%d-%H-%M-%S')
	session_name = 'KubiyaWG-' + session_date  # You can set a session name
	region_name = 'us-east-1'  # Specify the AWS region

	# Create an STS client using your default credentials (e.g., from your AWS CLI profile)
	sts_client = boto3.client('sts')
	# check to see if we need to assume a role from another role
	if (role_to_assume_from is not None):
		first_response = sts_client.assume_role(
		RoleArn=role_to_assume_from,
		RoleSessionName=session_name
	)
		# Extract temporary credentials
		first_credentials = first_response['Credentials']
		first_access_key = first_credentials['AccessKeyId']
		first_secret_key = first_credentials['SecretAccessKey']
		first_session_token = first_credentials['SessionToken']
		session = boto3.Session(
		aws_access_key_id=first_access_key,
		aws_secret_access_key=first_secret_key,
		aws_session_token=first_session_token
	)

	# Use the session to create an STS client
		sts_client_2 = session.client('sts')

	# Call the assume_role method to get temporary credentials for the new role
		response = sts_client_2.assume_role(
		RoleArn=role_arn,
		RoleSessionName=session_name
	)
		credentials = response['Credentials']
		access_key = credentials['AccessKeyId']
		secret_key = credentials['SecretAccessKey']
		session_token = credentials['SessionToken']
		return(access_key,secret_key,session_token)
	
	# We want to assume a role directly otherwise...
	response = sts_client.assume_role(
		RoleArn=role_arn,
		RoleSessionName=session_name
	)
	# Extract temporary credentials
	credentials = response['Credentials']
	access_key = credentials['AccessKeyId']
	secret_key = credentials['SecretAccessKey']
	session_token = credentials['SessionToken']
	return(access_key,secret_key,session_token)

#-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
def updateAMIWhitelist(amiID):
	APIKEY = get_secret('/prod/aetn.devops.ami.whitelist/api_key')['api_key']
	url = ' https://prod-devops-ami-whitelist.aetnd.io/prod/add_ami'
	headers = {
	"Accept": "application/json",
	"Content-Type": "application/x-www-form-urlencoded",
	"x-api-key": APIKEY
	}

	response = requests.request(
	"POST",
	url,
	headers=headers,
	data=json.dumps({"ami_id": amiID})
	)
	if (response.status_code == 201):
		print ('Whitelist updated Successfully')
	else:
		print('a Non 201 response code received: ',response.status_code, 'Response text:',response.text)

#-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
def updateParameter(parameters, key, value):
	for param in parameters:
		if param['ParameterKey'] == key:
			param['ParameterValue'] = value
			return parameters
	parameters.append({'ParameterKey': key, 'ParameterValue': value})	
	return parameters
#-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
def updateTag(tags,key,value):
	for tag in tags:
		if tag['Key'] == key:
			tag['Value'] = value
			return tags
	tags.append({'Key': key, 'Value': value})
	return tags
#-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
def updateWiregardStack(stackID, ImageID):
	[AccessKeyId,SecretAccessKey,SessionToken]=getAWSCreds(kubiya_admin_rolearn,kubiya_wg_rolearn)
	cf_client = boto3.client('cloudformation',
	aws_access_key_id=AccessKeyId,
	aws_secret_access_key=SecretAccessKey,
	aws_session_token=SessionToken)

	try:
		print('Updating Stack')
		print('Getting existing template parameters.')
		response = cf_client.get_template(StackName=stackID)
		template_body = response['TemplateBody']
		response = cf_client.describe_stacks(StackName=stackID)
		stack = response['Stacks'][0]
		tags = updateTag(stack.get('Tags', []),'aets',str(time.time()))
		parameters = updateParameter(stack.get('Parameters', []),'ImageId',latestAMI)
		capabilities = stack.get('Capabilities',[])
	except Exception as e:
		print(f"Error occurred while getting stack parameters: ", {e})
		sys.exit(1)
	try:
		response = cf_client.update_stack(
			StackName=stackID,
			TemplateBody=template_body,
			Parameters=parameters,
			Capabilities=capabilities,
			Tags=tags
		)
	# Print the stack ID or any other response details
		print(f"Stack update initiated: {response['StackId']}")
	except Exception as e:
		if ('no updates are to be performed' in str(e).lower()):
			print("No updates are to be performed.")
			sys.exit()
		else:
			print(f"Error updating stack: {e}")  
			sys.exit(1) 
	# Waiter for stack update completion
	waiter = cf_client.get_waiter('stack_update_complete')

	try:
		print("Waiting for stack update to complete...")
		waiter.wait(StackName=stackID)
		print("Stack update completed successfully.")
	except Exception as e:
		print(f"Stack update failed: {e}")

#-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
def updateAMIsecret(secret,amiID):
	secret_value=get_secret(secret)
	secret_value['ImageID']=amiID
	# Create a Secrets Manager client
	[AccessKeyId,SecretAccessKey,SessionToken]=getAWSCreds(kubiya_wg_rolearn)
	secrets_manager_client = boto3.client('secretsmanager',
	aws_access_key_id=AccessKeyId,
	aws_secret_access_key=SecretAccessKey,
	aws_session_token=SessionToken)
	# Prepare the parameters for update_secret
	update_params = {
		'SecretId': secret
	}
	update_params['SecretString'] = json.dumps(secret_value)
	# Call update_secret
	try:
		response = secrets_manager_client.update_secret(**update_params)
		print(f"Secret {secret} updated successfully, ARN: {response['ARN']}")
	except secrets_manager_client.exceptions.ResourceNotFoundException:
		print(f"Secret {secret} not found.")
	except secrets_manager_client.exceptions.InvalidRequestException as e:
		print(f"Invalid request: {e}")
	except secrets_manager_client.exceptions.InvalidParameterException as e:
		print(f"Invalid parameters: {e}")
	except secrets_manager_client.exceptions.ClientError as e:
		print(f"An error occurred: {e}")
#-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
def get_secret(secretVault):
	 # Create a Secrets Manager client
	[AccessKeyId,SecretAccessKey,SessionToken]=getAWSCreds(kubiya_wg_rolearn)	
	client = boto3.client('secretsmanager',
	aws_access_key_id=AccessKeyId,
	aws_secret_access_key=SecretAccessKey,
	aws_session_token=SessionToken,region_name='us-east-1')
	try:
		# Retrieve the secret
		response = client.get_secret_value(SecretId=secretVault)

		# Depending on the structure of the secret, you might need to parse the response
		if 'SecretString' in response:
			secret = json.loads(response['SecretString'])
		else:
			# If the secret is in binary form
			secret = json.loads(response['SecretBinary'])
		
		return secret
		#return secret[secretName]

	except NoCredentialsError:
		print("Credentials not available")
		return None
	except PartialCredentialsError:
		print("Incomplete credentials provided")
		return None
	except client.exceptions.ResourceNotFoundException:
		print(f"The requested secret {secret} was not found")
		return None
	except client.exceptions.InvalidRequestException as e:
		print(f"The request was invalid: {e}")
		return None
	except client.exceptions.InvalidParameterException as e:
		print(f"The request had invalid params: {e}")
		return None
#-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
def getAlpineVersions(alpine_version):
	# Create an EC2 client
	[AccessKeyId,SecretAccessKey,SessionToken]=getAWSCreds(kubiya_wg_rolearn)	
	ec2_client = boto3.client('ec2',  aws_access_key_id=AccessKeyId,
	aws_secret_access_key=SecretAccessKey,
	aws_session_token=SessionToken,region_name='us-east-1')

	# Call describe_images to retrieve a list of AMIs filtered by Alpine Linux
	response = ec2_client.describe_images(
		Owners=['538276064493'],
		#Query=['reverse(sort_by(Images, &CreationDate))[].[ImageId, Name, CreationDate]'],
		Filters=[
			{
				'Name': 'name',
				'Values': ['alpine-' + alpine_version + '*-x86_64-uefi-tiny*']  # Filter for Alpine Linux AMIs
			}
		]
	)

	# Extract the AMI details
	ami_raw = response.get('Images', [])
	amis = sorted(ami_raw, key=lambda x: x['CreationDate'], reverse=True)
	#print(amis[0]['ImageId'],amis[0]['Name'],amis[0]['CreationDate'])
	#for ami in amis:   
	#    print('ImageId: ', ami['ImageId'], ' Name: ', ami['Name'], ' CreationDate: ', ami['CreationDate'])
	return(amis[0]['ImageId'])
#-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
#     
cmdargs=argparse.ArgumentParser(description='Check and update the Wireguard AMI')
cmdargs.add_argument('--action', help='check or update', required=True)
cmdargs.add_argument('--environment', help='prod or dev', required=True)
args=cmdargs.parse_args()

check=True
run = False
try:
	if (args.action == 'check'):
		check=True
	elif (args.action == 'update'):
		run=True
		check=False
	else:
		print('action should be either check or update, exiting')
		sys.exit(1)
	
	if (args.environment == 'prod'):
		WGSecret='/prod/aetn.devops.wireguard/ami-id'
		env='prod'
	else:
		WGSecret='/dev/aetn.devops.wireguard/ami-id'
		env='dev'
except:
	print('Please select check or update, and specify the environment as prod or dev')
	print('Check will only check for new AMI, update will check and update the AMI.')
	sys.exit(1)

kubiya_wg_rolearn='arn:aws:iam::433624884903:role/kubiya-wireguard-role'
kubiya_admin_rolearn='arn:aws:iam::433624884903:role/kubiya-cloudformation-execution-role'
alpineVersion=get_secret(WGSecret)['AlpineVersion']
wireGardCFStackID=get_secret(WGSecret)['WireGardCFStackID']
latestAMI=getAlpineVersions(alpineVersion)
storedAMI=get_secret(WGSecret)['ImageID']

if (latestAMI != storedAMI):
	if (check == True):
		print('There is a new AMI present:',latestAMI)
		sys.exit(0)
	if (run == True):
		print ('There is a new AMI present:',latestAMI,'updating secret, and whitelisting AMI.')
		updateAMIsecret(WGSecret,latestAMI)
		updateAMIWhitelist(latestAMI)
		updateWiregardStack(wireGardCFStackID, latestAMI)
else:
	print ('No new AMI present in ',env,': Current: ',storedAMI, ' Latest: ',latestAMI,'no changes made.')
	sys.exit()
