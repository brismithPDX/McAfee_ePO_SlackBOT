#requires installation of python3 and SlackClient Extensions

#this is used one time to find your bot ID for use in the main HealthCheckBot.py script

import os
from slackclient import SlackClient

BOT_NAME = 'ePO_BOT'
SLACK_BOT_TOKEN = '' #this is not super secure nor good. dont put your slack tokens in the source code folks. use a evriomental variable or such instead.

slack_client = SlackClient(SLACK_BOT_TOKEN)

if __name__ =="__main__":
    api_call = slack_client.api_call("users.list")
    if api_call.get('ok'):
        users = api_call.get('members')
        for user in users:
            if 'name' in user and user.get('name') == BOT_NAME:
                print("Bot ID for '"+user['name'] +"' is " + user.get('id'))
    else :
        print("could not find bot user with the name " + BOT_NAME)