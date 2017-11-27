"""
devsecops.py

This is what our team came up with for offering Unicorn group DevSecOps...
Maybe a semi standard solution would have been better like:
https://aws.amazon.com/answers/devops/aws-cloudformation-validation-pipeline/
or
https://aws.amazon.com/blogs/devops/implementing-devsecops-using-aws-codepipeline/

But... On the otherhand, this one is small and fast, and available as an API..
So we can offer DevSecOps as a service to Unicorn divisions, via a handy API endpoint.
You need to implement static analysis via python, against the YAML templates,
and enforce our policies without failure.

Another team will *hopefully* close the loop doing dynamic analysis with:
AWS Cloudwatch Events
AWS Config Rules

or things like
https://github.com/capitalone/cloud-custodian
https://github.com/Netflix/security_monkey

And because DevSecOps is also about broadening the shared responsibility of security,
as well as automation, we have a basic function here for publishing to a Slack channel.

"""
import ruamel.yaml
import json
import base64
from urllib.parse import urljoin
from urllib.parse import urlencode
import urllib.request as urlrequest

#Configure these to Slack for ChatOps
SLACK_CHANNEL = '#general'
HOOK_URL = "https://hooks.slack.com/services/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"

# Helper Function to enable us to put visibility into chat ops
# The Slack channel to send a message to stored in the slackChannel environment variable
def send_slack(message, username="SecurityBot", emoji=":exclamation:"):
    if not HOOK_URL:
        print("Slack not setup")
        return None
    slack_message = {
        'channel': SLACK_CHANNEL,
        'text': message,
         "username": username
    }
    opener = urlrequest.build_opener(urlrequest.HTTPHandler())
    payload_json = json.dumps(slack_message)
    data = urlencode({"payload": payload_json})
    req = urlrequest.Request(HOOK_URL)
    response = opener.open(req, data.encode('utf-8')).read()
    return response.decode('utf-8')

# Define a YAML reader for parsing Cloudformation to handle !Functions like Ref
def general_constructor(loader, tag_suffix, node):
    return node.value
ruamel.yaml.SafeLoader.add_multi_constructor(u'!', general_constructor)

# Define basic security globals
SECURE_PORTS = ["443","22"]
DB_PORTS = ["3306"]
TAGS = ["Name", "Role", "Owner", "CostCenter"]

#Our DevSecOps Logic
def handler(event, context):
    yaml = base64.b64decode(event['b64template'])
    cfn = ruamel.yaml.safe_load(yaml)
    # Policy 0 is no Dangerous ports on 0.0.0.0/0
    result = {"pass":True,"policy0":0, "policy1":0, "policy2":0, "policy3":0, "errors":[]}
    send_slack("BUILD: Starting DevSecOps static code analysis of CFN template: {}".format(cfn['Description']))

    #Now we loop over resources in the template, looking for policy breaches
    for resource in cfn['Resources']:
        
        #send_slack("BUILD: Found SG rule: {}".format(cfn))

        #Test for Security Groups for Unicorn Security policy0
        if cfn['Resources'][resource]["Type"] == """AWS::EC2::SecurityGroup""":
            if "SecurityGroupIngress" in cfn['Resources'][resource]["Properties"]:
                for rule in cfn['Resources'][resource]["Properties"]['SecurityGroupIngress']:

                    send_slack("BUILD: Found SG rule: {}".format(rule))

                    if 'CidrIp' in rule:
                        #Test that SG ports are only 22 or 443 if open to /0
                        if rule["FromPort"] == rule["ToPort"]:
                            if (rule["FromPort"] not in SECURE_PORTS or rule["ToPort"] not in SECURE_PORTS) and rule["CidrIp"] == '0.0.0.0/0':
                                result['pass'] = False
                                result['policy0'] += 1 #Add one to our policy fail counter
                                result["errors"].append("policy0: Port {} not allowed for /0".format(rule["FromPort"]))

                        #lets catch ranges (i.e 22-443)
                        if rule["FromPort"] != rule["ToPort"] and rule["CidrIp"] == '0.0.0.0/0':
                            result['pass'] = False
                            result['policy0'] += 1 #Add one to our policy fail counter
                            result["errors"].append("policy0: Port range {}-{} is not allowed for /0".format(rule["FromPort"],rule["ToPort"]))

                        #Policy 0 Subrule2: Any Amazon RDS for MySQL can be accessed only by web servers via port 3306
                        if rule["FromPort"] in DB_PORTS and rule["ToPort"] in DB_PORTS:
                            result['pass'] = False
                            result['policy0'] += 1 #Add one to our policy fail counter
                            result["errors"].append("policy0: Port {} is not allowed to use CidrIP to restrict access. Please use the security group named WebServerSecurityGroup".format(rule["FromPort"]))
   
                    #Policy 0 Subrule2: Any Amazon RDS for MySQL can be accessed only by web servers via port 3306
                    if 'SourceSecurityGroupName' in rule:
                        if rule["FromPort"] in DB_PORTS and rule["ToPort"] in DB_PORTS and rule["SourceSecurityGroupName"] != 'WebServerSecurityGroup':
                            result['pass'] = False
                            result['policy0'] += 1 #Add one to our policy fail counter
                            result["errors"].append("policy0: SourceSecurityGroupName: {} is not allowed for a DB security group".format(rule["SourceSecurityGroupName"]))
    
        #Policy 0 Subrule3: Any Amazon S3 bucket cannot be publically accessible
        if cfn['Resources'][resource]["Type"] == """AWS::S3::Bucket""":
            if "Properties" in cfn['Resources'][resource]:
                if "AccessControl" in cfn['Resources'][resource]["Properties"]:
                    if cfn['Resources'][resource]["Properties"]["AccessControl"] == 'PublicReadWrite' or cfn['Resources'][resource]["Properties"]["AccessControl"] == 'PublicRead':
                        result['pass'] = False
                        result['policy0'] += 1 #Add one to our policy fail counter
                        result["errors"].append("policy0: PublicReadWrite on Bucket")
                        
        #Policy1 Subrule1: IAM Policy Elements: Action *, IAM or Organisations cannot be specified in "IAM inline policies" to create IAM users. 
        if cfn['Resources'][resource]["Type"] == """AWS::IAM::User""":
            if "Properties" in cfn['Resources'][resource]:
                if "Policies" in cfn['Resources'][resource]["Properties"]:
                    for rule in cfn['Resources'][resource]["Properties"]['Policies']: #['Condition']['StringLike']['aws:Referer']:
                    
                        send_slack("BUILD: Found policies: {}".format(rule))
                    
                        for iam in rule['PolicyDocument']['Statement']:                                                
                            send_slack("BUILD: Found Action: {}".format(iam["Action"][0]))
                            #print(iam["Action"][0])
                        
                            if iam['Effect'] == 'Allow':
                                if 'organizations:' in iam["Action"] or 'iam:' in iam["Action"] or '*' in iam["Action"][0]:
                                    result['pass'] = False
                                    result['policy1'] += 1 #Add one to our policy fail counter
                                    result["errors"].append("policy1 subrule1: {} are not allowed as inline policy. Action *, IAM or Organisations cannot be specified in IAM inline policies.".format(iam["Action"]))
                
                #Policy 1 Subrule2: Only support or cloudwatch related "IAM managed policies" can be specified to create IAM users.                 
                if "ManagedPolicyArns" in cfn['Resources'][resource]["Properties"]:
                    for rule in cfn['Resources'][resource]["Properties"]["ManagedPolicyArns"]: 
                        
                        send_slack("BUILD: Found policies: {}".format(rule))
                        print(rule)
                        
                        if 'AWSSupportAccess' not in rule and 'SupportUser' not in rule and 'CloudWatch' not in rule: 
                            result['pass'] = False
                            result['policy1'] += 1 #Add one to our policy fail counter
                            result["errors"].append("policy1 subrule2: IAM managed policy {} is not allowed.  Only support or cloudwatch related IAM managed policies can be specified to create IAM users.".format(rule)) 
       
        #Policy1 Subrule3: Any EC2 must be created with IAM role to access other services
        if cfn['Resources'][resource]["Type"] == """AWS::EC2::Instance""":
            if 'IamInstanceProfile' not in cfn['Resources'][resource]["Properties"]:
                result['pass'] = False
                result['policy1'] += 1 #Add one to our policy fail counter
                result["errors"].append("policy1 subrule3: Any EC2 must be created with IAM role to access other services.")
         
            #Policy2 Subrule2: Any EC2 has to have a tags Name, Role, Owner, CostCenter
            if 'Tags' not in cfn['Resources'][resource]["Properties"]:
                result['pass'] = False
                result['policy2'] += 1 #Add one to our policy fail counter
                result["errors"].append("Policy2 Subrule2: Any EC2 has to have a tags Name, Role, Owner, CostCenter.")
            else:
                for tag in cfn['Resources'][resource]["Properties"]["Tags"]:
                    send_slack("BUILD: Found policies: {}".format(tag))
                    
                    if tag['Key'] not in TAGS:
                        result['pass'] = False
                        result['policy2'] += 1 #Add one to our policy fail counter
                        result["errors"].append("Policy2 Subrule2: {} is not allowed as tag name. Any EC2 has to have a tags Name, Role, Owner, CostCenter.".format(tag['Key']))
        
        #Policy3 Subrule1: Any EBS volume for EC2 (except root volume) and RDS needs to be encrypted.
        if "BlockDeviceMappings" in cfn['Resources'][resource]["Properties"]:
            for ebs in cfn['Resources'][resource]["Properties"]["BlockDeviceMappings"]:
                
                #send_slack("BUILD: Found policies: {}".format(ebs['Ebs']['Encrypted']))
                
                if 'Encrypted' in ebs['Ebs']:
                    if ebs['Ebs']['Encrypted'] == 0:
                        result['pass'] = False
                        result['policy3'] += 1 #Add one to our policy fail counter
                        result["errors"].append("Policy3 Subrule1: {} is needs to be encrypted".format(ebs['DeviceName']))
                else:
                        result['pass'] = False
                        result['policy3'] += 1 #Add one to our policy fail counter
                        result["errors"].append("Policy3 Subrule1: {} is needs to be encrypted".format(ebs['DeviceName']))
                     
        #Policy2 Subrule1: ELB logs need to be enabled. 
        if cfn['Resources'][resource]["Type"] == """AWS::ElasticLoadBalancing::LoadBalancer""":
            if 'AccessLoggingPolicy' not in cfn['Resources'][resource]["Properties"]:
                result['pass'] = False
                result['policy2'] += 1 #Add one to our policy fail counter
                result["errors"].append("Policy2 Subrule1: AccessLoggingPolicy doesn't exist. ELB logs need to be enabled.")
            else:
                if cfn['Resources'][resource]["Properties"]["AccessLoggingPolicy"]["Enabled"] == 0:
                    result['pass'] = False
                    result['policy2'] += 1 #Add one to our policy fail counter
                    result["errors"].append("Policy2 Subrule1: ELB logs is disbled. It needs to be enabled.")                    

        #Policy2 Subrule1: CloudFront logs need to be enabled. 
        if cfn['Resources'][resource]["Type"] == """AWS::CloudFront::Distribution""":
            if 'Logging' not in cfn['Resources'][resource]["Properties"]["DistributionConfig"]:
                result['pass'] = False
                result['policy2'] += 1 #Add one to our policy fail counter
                result["errors"].append("Policy2 Subrule1: Logging doesn't exist. CloudFront logs need to be enabled.")
        
            #Policy3 Subrule2: Any traffic to Clondfront needs to be encrypted by using https protocol
            if 'ViewerProtocolPolicy' in cfn['Resources'][resource]["Properties"]["DistributionConfig"]["DefaultCacheBehavior"]:
                if cfn['Resources'][resource]["Properties"]["DistributionConfig"]["DefaultCacheBehavior"]["ViewerProtocolPolicy"] != "https-only":
                    result['pass'] = False
                    result['policy3'] += 1 #Add one to our policy fail counter
                    result["errors"].append("Policy3 Subrule2: ViewerProtocolPolicy {} is not allowed. https-only.".format(cfn['Resources'][resource]["Properties"]["DistributionConfig"]["DefaultCacheBehavior"]["ViewerProtocolPolicy"]))
            
        #Policy3 Subrule1: Any EBS volume for EC2 (except root volume) and RDS needs to be encrypted.
        if cfn['Resources'][resource]["Type"] == """AWS::RDS::DBInstance""":
            
            if "StorageEncrypted" in cfn['Resources'][resource]["Properties"]:        
                if cfn['Resources'][resource]["Properties"]["StorageEncrypted"] == 0:        
                    result['pass'] = False
                    result['policy3'] += 1 #Add one to our policy fail counter
                    result["errors"].append("Policy3 Subrule1: The value of StorageEncrypted property needs to be true.  RDS needs to be encrypted.")
            else:
                result['pass'] = False
                result['policy3'] += 1 #Add one to our policy fail counter
                result["errors"].append("Policy3 Subrule1: StorageEncrypted property is required. RDS needs to be encrypted.")
                     
    # Now, how did we do? We need to return accurate statics of any policy failures.
    if not result["pass"]:
        for err in result["errors"]:
            print(err)
            send_slack(err, username="BuildSecurityBotFAIL", emoji=":exclamation:")
        send_slack("Failed DevSecOps static code analysis. Please Fix policy breaches.", username="SecurityBotFAIL", emoji=":exclamation:")
    else:
        send_slack("Passed DevSecOps static code analysis Security Testing", username="SecurityBotPASS", emoji=":white_check_mark:")
    return result
