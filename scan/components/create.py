#!/usr/bin/env python3

import os
from termcolor import colored
from discord_webhook import DiscordWebhook, DiscordEmbed
import socket

def initialize():
    global webhook
    webhook = ""

def checkdir(location):
    if os.path.isdir(location):
        if location.endswith(('/')):
            logdata = colored("[*] SAVING PROJECT IN {0}".format(location), 'yellow')
        else:
            location = location + '/'
            logdata = colored("[*] SAVING PROJECT IN {0}".format(location), 'yellow')
        appendlog(location, logdata)
    else:
        projfile(location)
        appendlog(location, colored("[!] CREATING DIR {0}!".format(location), 'red'))
    return location


def projfile(location):
    if os.path.exists(location):
        appendlog(location, colored("[*] {0} ALREADY EXISTS".format(location), 'yellow'))
    else:
        os.makedirs(location)
    return location


def creatfile(location, host):
    if os.path.exists(location + '/' + host):
        appendlog(location, colored("[*] {0} ALREADY EXISTS IN {1}".format(host, location), 'yellow'))
    else:
        os.mkdir(location + '/' + host)


def appendlog(location, message):
    log = open(location + "scan.log", "a+")
    print(message)
    log.write(message + "\n")
    log.close()

def welcome(webhook):
    if webhook:
        username = socket.gethostname()
        webhook = DiscordWebhook(url=webhook)
        embed = DiscordEmbed(title="Welcome", description="Scanner Running on host {}".format(username))
        embed.set_author(name="Scan.py", url="https://github.com/ptf569/scan")
        embed.set_footer(text="Good Luck!!")
        webhook.add_embed(embed)
        response = webhook.execute()
        return response

def discord(webhook, action, message):
    if webhook:
        username = socket.gethostname()
        webhook = DiscordWebhook(url=webhook)
        embed = DiscordEmbed(title=action, description=message)
        embed.set_author(name=username)
        embed.set_timestamp()
        webhook.add_embed(embed)
        response = webhook.execute()
        return response
