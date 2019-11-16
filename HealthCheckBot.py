#requires installation of
#   python3, SlackClient Extensions, hashlib, requests
import os
import time
from datetime import datetime
import slack
import requests
from requests.auth import HTTPBasicAuth
import _thread
import json

# Disables 'InsecureRequestWarning' warning from urllib3
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


## Control variables, Global Defaults, and Configuration ##
DEBUG = 0
MaxCommandLen = 10
#Bot Configuration
BOT_NAME = "McBOT"
Default_Channel = "#csa_bots"
BOT_ID = 'U5YBN0ZB6'

#ePO Connection Configuration
infection_search_window = 3888000000
webclient = None 

# Access EPO credentials and Slackbot Token
# Credential format is: EPO_Username\nEPO_Password\nSlackToken
with open("credentials.txt", 'r') as cred_file:
    CROMWELL_usr = cred_file.readline().strip()
    CROMWELL_pass = cred_file.readline().strip()
    SLACK_BOT_TOKEN = cred_file.readline().strip()

#logFile Configuration
ErrorFile = ".\OperationLogs\ErrorLog.log"
AuditFile = ".\OperationLogs\AuditLog.log"


AT_BOT = "<@" + BOT_ID + ">"
## End of Configuration, Control Variables, and Global Defaults##

##Begin Bot Operations
slack_client = slack.RTMClient(token=SLACK_BOT_TOKEN)

#Core BOT Functions
@slack_client.run_on(event='message')
def parse_slack_output(**slack_rtm_output):   #Slack channel parser
    if slack_rtm_output and len(slack_rtm_output) > 0:
        data = slack_rtm_output['data']
        global webclient
        webclient = slack_rtm_output['web_client']
        try:
            if AT_BOT in data['text']:
                # return text after the @ mention, whitespace removed
                command, channel = data['text'].split(AT_BOT)[1].strip().lower(), data['channel']
                try:
                    _thread.start_new_thread(command_dict[command[:MaxCommandLen]], (channel,  command[MaxCommandLen: MaxCommandLen+15]))
                except:
                    response = "Sorry I am not familiar with that command, type help for more details"
                    webclient.chat_postMessage(channel=channel, text=response, as_user=True) 
        except Exception as inst:
            if DEBUG == 1:
                log_ToFile("Exception instance encountered: " + inst, "Error")

#Displays help in requested channel
def display_help(channel, usr_args):
    response = """ Hi, I am """ + BOT_NAME + "!" + """
    I am here to help technicans check a computers McAfee Health Status.
    I accept commands in the \""""+ BOT_NAME + """ [Command]\" format.

    Right now i can only do a few things but they include:
    getupdate - has me run a on demand update check
    help - prints this help page
    ? - see "help"
    namecheck [computer-name] - has me run a McAfee ePO health check on the client located on [computer-name] Note: computername must be 15chars or less.
    """
    webclient.chat_postMessage(channel=channel, text=response, as_user=True)

def mac_healthchk(response):                #Evaluates OSX Health check data
    if response.find("On-Access Scan Enabled: true") != -1 and response.find("McAfee Agent Installed: true") != -1 and response.find("Definitions Up To Date (AMCore Content): true") != -1:
        final_response = "== Health Check PASSED ==" + response
    else:
        final_response = "== Health Check FAILED ==" + response
    return final_response

def win_healthchk(response):                #Evaluates Windows Health check data
    if response.find("false") == -1 and response.find("Definitions Up To Date (AMCore Content): true") != -1:
        final_response = "== Health Check PASSED ==" + response
    else:
        final_response = "== Health Check FAILED ==" + response
    return final_response

def InfectionHistory(usr_args):
    #perform search on ePO server
    ServerLocation = ''
    url = ServerLocation + '/remote/core.executeQuery?target=EPOEvents&select=(select EPOEvents.DetectedUTC EPOEvents.EventTimeLocal EPOEvents.TargetHostName EPOEvents.ThreatName)&where=(where ( and ( newerThan EPOEvents.DetectedUTC '+ str(infection_search_window) +'   ) ( or ( threatcategory_belongs EPOEvents.ThreatCategory "av"  ) ( threatcategory_belongs EPOEvents.ThreatCategory "av.detect"  ) ( threatcategory_belongs EPOEvents.ThreatCategory "av.detect.heuristics"  ) ( threatcategory_belongs EPOEvents.ThreatCategory "av.detect.heuristics"  )  ) ( eq EPOEvents.AnalyzerHostName "'+ usr_args +'"  )  ) )'
    query_result = requests.get(url, auth=HTTPBasicAuth(CROMWELL_usr,CROMWELL_pass), verify=False)
    
    if DEBUG == 1:
        count = query_result.text.count("E")
        print("\n\nquery result count = " + str(count) + "\n\n")
        print("Query Text = "+query_result.text+"\n\n===\n\n")
    if(query_result.text.count("E") > 2):    
        return True
    else:
        return False

#Launches a McAfee health check for user define computer name 
def run_namecheck(channel, usr_args):
    #give user search launch notice
    response = "Starting a McAfee ePO Client Health Check, please be patient..."
    webclient.chat_postMessage(channel=channel, text=response, as_user=True)

    #perform search on ePO server
    ServerLocation = ''
    url = ServerLocation + '/remote/core.executeQuery?target=EPOLeafNode&select=(select AM_CustomProps.AVCMGRbComplianceStatus EPOLeafNode.NodeName EPOComputerProperties.OSType EPOComputerProperties.OSBuildNum EPOLeafNode.LastUpdate AM_CustomProps.bAPEnabled AM_CustomProps.bOASEnabled EPOProdPropsView_EPOAGENT.productversion EPOProdPropsView_ENDPOINTSECURITYPLATFORM.productversion EPOProdPropsView_TIECLIENTMETA.productversion AM_CustomProps.ManifestVersion )&where=(where(eq+EPOLeafNode.NodeName "' + usr_args + '"))'
    query_result = requests.get(url, auth=HTTPBasicAuth(CROMWELL_usr,CROMWELL_pass), verify=False)

    #Response editing for user readability
    response = (query_result.text).replace("OK:", "")
    response = response.replace("AMCore Content Compliance Status: 1", "Definitions Up To Date (AMCore Content): true")
    response = response.replace("AMCore Content Compliance Status: 0", "Definitions Up To Date (AMCore Content): false")
    response = response.replace("AMCore Content Compliance Status: null", "Definitions Up To Date (AMCore Content): unknown")
    response = response.replace("Access Protection Enabled: null", "Access Protection Enabled: unknown")
    response = response.replace("On-Access Scan Enabled: null", "On-Access Scan Enabled: unknown")

    
    if DEBUG == 1:
        print("\n run_namecheck - response user readability == DEBUG result output: \n" + response)

    #operating system discrimination to apply proper method of health check verification 
    if response.find("System Name:") == -1:
        response = "\n I could not find a machine with that name. \n The client may be broken, not managed by the production McAfee server, or the computer name is wrong."
    if response.find("Mac OS X") != -1:
        response = mac_healthchk(response)
    else:
        response = win_healthchk(response)
    
    #perform Multiple Infection history check
    if(InfectionHistory(usr_args)):
        response += "\n\n== WARNING! ==\n\n This machine has multiple major infections in the last 45days! \n== RE-IMAGE REQUIRED! ==\n"

    #send user final response
    webclient.chat_postMessage(channel=channel, text=response, as_user=True)

#Protects run_namechk from invalid characters 
def counter_SQLI(channel,usr_args):
    panic = False
    if usr_args.find("\"") != -1:
        panic = True
    if usr_args.find(")") != -1:
        panic = True
    if usr_args.find("'") != -1:
        panic = True
    if usr_args.find(";") != -1:
        panic = True
    if usr_args.find("=") != -1:
         panic = True
    if usr_args.find("*") != -1:
        panic = True     
    if usr_args.find("+") != -1:
        panic = True
    if usr_args.find("!") != -1:
        panic = True
    if usr_args.find("^") != -1:
        panic = True
    if usr_args.find("#") != -1:
        panic = True
    if usr_args.find(" ") != -1:
        panic = True
    if panic:
        if DEBUG == 1:
            print("SQLI Detected at: " + time.strftime("%d/%m/%Y %H:%M") + " In Channel: " + channel)
            print("Bad Query: " + usr_args)
            print("Query Abandoned!")
            log_ToFile(("SQLI Detected in Channel: " + channel + ", Query Abandoned!!, Bad Query: " + usr_args), "Audit")

        response = "SQLI Detected: Query Abandoned, This alert has been logged and the administrator notified!"
        webclient.chat_postMessage(channel=channel, text=response, as_user=True)
    else:
        run_namecheck(channel, usr_args)

#Allows logging of events to error and audit logs
def log_ToFile(message, level):

    if DEBUG == 1:
        print(message)
        print(level)
    logging_type_dict = {
        "error" : ErrorFile,
        "Error" : ErrorFile,
        "Audit" : AuditFile,
        "audit" : AuditFile,
    }

    current_file = open(logging_type_dict[level], 'w+')
    current_file.write(level + ": @" + "{:%B %d, %Y, %H:%M:%S}".format(datetime.now()) + " - " + message)
    current_file.close()


#functions command dictionary
command_dict = {
    "?" : display_help,
    "help" : display_help,
    "Help" : display_help,
    "namecheck " : counter_SQLI,
    "Namecheck " : counter_SQLI,
}

#Main BOT control
if __name__ == "__main__":
    #check / verify McAfee ePO API credentials
    try:

        if CROMWELL_pass == "" or CROMWELL_usr == "":
            raise SystemExit(BOT_NAME + " FAILED to locate ePO API credentials; please provide credentails and try again")

        ServerLocation = ''
        url = ServerLocation + '/remote/core.help'
        query_result = requests.get(url, auth=HTTPBasicAuth(CROMWELL_usr,CROMWELL_pass), verify=False)

        if query_result.text.find("<title> - Error report</title>") != -1:
            if DEBUG == 1:
                print("\n Startup - Credential Check == DEBUG query_result output: \n" + query_result.text)
            raise SystemExit("Connected to ePO API but failed to verify credentials; check credentials and restart")
    except:
        if DEBUG == 1:
            print("\n Startup - Credential Check FAILED")
        raise SystemExit(BOT_NAME + " FAILED to verify ePO API credentials; please check credentials & connection before trying again")
    
    try:
        slack_client.start()
    except RuntimeError as re:
        log_ToFile(re, "Error")
    except ValueError :
        pass