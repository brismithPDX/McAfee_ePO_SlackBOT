#requires installation the following support libraries
#   python3, SlackClient Extensions, requests

import os
import time
from datetime import datetime, timedelta
from slackclient import SlackClient
import requests
from requests.auth import HTTPBasicAuth


##Control variables and Global Defaults
DEBUG = 0
MaxCommandLen = 10
BOT_NAME = "ePO_BOT"
Defualt_Channel = ""
BOT_ID = ''
SLACK_BOT_TOKEN = ''

ePO_SERVER_usr = ""
ePO_SERVER_pass = ""
ServerLocation = "https://your_ePO_server.local:8443"

AT_BOT = "<@" + BOT_ID + ">"

##Begin Bot Operations

slack_client = SlackClient(SLACK_BOT_TOKEN)

#Core BOT Functions
def parse_slack_output(slack_rtm_output):   #Slack channel parser: DO NOT EDIT
    output_list = slack_rtm_output
    if output_list and len(output_list) > 0:
        for output in output_list:
            if output and 'text' in output and AT_BOT in output['text']:
                # return text after the @ mention, whitespace removed
                return output['text'].split(AT_BOT)[1].strip().lower(), \
                       output['channel']
    return None, None

def display_help(channel, usr_args):        #Displays help in requested channel
    response = """ Hi, I am """ + BOT_NAME + "!" + """
    I am here to help technicans check a computers McAfee Health Status.
    I accept commands in the \""""+ BOT_NAME + """ [Command]\" format.

    Right now i can only do a few things but they include:
    getupdate - has me run a ondemand update check
    help - prints this help page
    ? - see "help"
    namecheck [computer-name] - has me run a McAfee ePO health check on the client located on [computer-name] Note: computername must be 15chars or less.
    """
    slack_client.api_call("chat.postMessage", channel=channel, text=response, as_user=True)

def mac_healthchk(response):                #Evaluates OSX Health check data
    if response.find("On-Access Scan Enabled: true") != -1 and response.find("Managed State: true") != -1 and response.find("AMCore Content Compliance Status: true") != -1:
        final_response = "== Health Check PASSED ==" + response
    else:
        final_response = "== Health Check FAILED ==" + response
    return final_response
def win_healthchk(response):                #Evaluates Windows Health check data
    if response.find("false") == -1 and response.find("AMCore Content Compliance Status: true") != -1:
        final_response = "== Health Check PASSED ==" + response
    else:
        final_response = "== Health Check FAILED ==" + response
    return final_response
def run_namecheck(channel, usr_args):       #Launches a McAfee health check for user define computer name 
    #check to insure credentials are available
    if ePO_SERVER_pass == "" or ePO_SERVER_usr == "":
        slack_client.api_call("chat.postMessage", channel=channel, text=response, as_user=True)
    
    #give user search launch notice
    response = "Starting a McAfee ePO Clienth Health Check, please be patitent..."
    slack_client.api_call("chat.postMessage", channel=channel, text=response, as_user=True)

    #perform search
    url = ServerLocation + '/remote/core.executeQuery?target=EPOLeafNode&select=(select AM_CustomProps.AVCMGRbComplianceStatus EPOLeafNode.NodeName EPOComputerProperties.OSType EPOLeafNode.LastUpdate EPOLeafNode.ManagedState AM_CustomProps.bAPEnabled AM_CustomProps.bOASEnabled)&where=(where(eq+EPOLeafNode.NodeName "' + usr_args + '"))'
    query_result = requests.get(url, auth=HTTPBasicAuth(ePO_SERVER_usr,ePO_SERVER_pass), verify=False)

    #Response editing for user readability
    response = (query_result.text).replace("OK:", "")
    response = response.replace("Managed State: 1", "Managed State: true")
    response = response.replace("AMCore Content Compliance Status: 1", "AMCore Content Compliance Status: true")
    
    #operating system discrimination to apply proper method of health check verification 
    if response.find("System Name:") == -1:
        response = "Sorry, I could not find a machine with that name. The client may be broken, not managed by the production McAfee server, or the computer name is wrong."
    if response.find("Mac OS X") != -1:
        response = mac_healthchk(response)
    else:
        response = win_healthchk(response)
    
    #send user final repsonse
    slack_client.api_call("chat.postMessage", channel=channel, text=response, as_user=True)
def counter_SQLI(channel,usr_args):         #Protects run_namechk from invalid charicters 
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
        print("SQLI Detected at: " + time.strftime("%d/%m/%Y %H:%M") + " In Channel: " + channel)
        print("Bad Query: " + usr_args)
        print("Query Abandoned!")
        
        response = "SQLI Detected: Query Abandoned, This alert has been logged and the Administator Notified!"
        slack_client.api_call("chat.postMessage", channel=channel, text=response, as_user=True)
    else:
        run_namecheck(channel, usr_args)

commmand_dict = {                           #functions command dictonary
    "help" : display_help,
    "?" : display_help,
    "namecheck " : counter_SQLI,
}

if __name__ == "__main__":                  #Main BOT control
    #bot start up
    READ_WEBSOCKET_DELAY = 1
    
    if slack_client.rtm_connect():  #Establish connection to slack.com
        print(BOT_NAME + " is running and connected to slack.com") 

        while True: #Bot Operating Loop
            
            #Search for commands
            try:
                command, channel = parse_slack_output(slack_client.rtm_read())
            except:
                print("Connection to slack.com FAILED... " + BOT_NAME + " could not perform slack_client.rtm_read()!")
            #Process commands if found
            if command and channel:

                if DEBUG == 1:
                    print(command)
                    print(command[:MaxCommandLen])
                    print(command[MaxCommandLen: MaxCommandLen+15])
               
                #Attempt to run users query
                try:
                    commmand_dict[command[:MaxCommandLen]](channel, command[MaxCommandLen: MaxCommandLen+15])
                except:
                    response = "Sorry I am not familiar with that command, type help for more details"
                    slack_client.api_call("chat.postMessage", channel=channel, text=response, as_user=True) 
    
            time.sleep(READ_WEBSOCKET_DELAY)
    else: #Handle Connection Failure
        if DEBUG == 1:
            print("Connection to slack.com FAILED... " + BOT_NAME + " could not establish connection!")
            print("Check slack token and botID before restarting " + BOT_NAME + "!")

