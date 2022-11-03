import collections

try:
    collectionsAbc = collections.abc
except AttributeError:
    collectionsAbc = collections

import logging
import os
import requests
import ipaddress
import socket
import json
from airtable import Airtable
from threading import Thread
from flask import Flask, json, jsonify, request
from flask_cors import CORS, cross_origin
from time import sleep

AIRTABLE_TOKEN = "keyjbgeI6H6HAmzhL"
AIRTABLE_BASE_ID = "appQDBFubiLHNatKx"
AIRTABLE_URL = f"https://api.airtable.com/v0/{AIRTABLE_BASE_ID}"
threadCount = 0

def get_scan_records():
    airtable = Airtable(AIRTABLE_BASE_ID, 'Scan', AIRTABLE_TOKEN)
    response = airtable.get_all(fields=["Target"], filterByFormula="{Master}='34.236.192.204'")
    return response 

def save_to_found(host):
    # airtable = Airtable(AIRTABLE_BASE_ID, 'Found', AIRTABLE_TOKEN)
    # Upload New
    url = f"{AIRTABLE_URL}/Found"
    headers = {"Authorization" : "Bearer " + AIRTABLE_TOKEN, "Content-Type" : "application/json"}
    
    upload_data = {"IP" : host}
    upload_dict = {"records" : [{"fields" : upload_data}], 
               "typecast" : False}        
    upload_json = json.dumps(upload_dict)
    
    response = requests.post(url, data=upload_json, headers=headers)

runningList = []
foundCount = {}
def servertest(host, cidr):
    global threadCount, foundCount
    port = 7999
    args = socket.getaddrinfo(host, port, socket.AF_INET, socket.SOCK_STREAM)
    for family, socktype, proto, canonname, sockaddr in args:
        s = socket.socket(family, socktype, proto)
        s.settimeout(1)
        try:
            s.connect(sockaddr)
        except socket.error:
            threadCount -= 1
            return False
        else:
            s.close()
            threadCount -= 1
            runningList.append(host)
            foundCount[cidr] += 1
            # print(host, ' works')
            # save_to_found(host)
            return True

api = Flask(__name__)

# @api.route('/api/runningList', methods=['GET'])
# @cross_origin()
def get_runningList():
    response = get_scan_records()
    global runningList
    runningList = []
    
    for record in response:
        # print((record.get('fields')).get('Target'))
        cidr = (record.get('fields')).get('Target')
        global foundCount
        foundCount[cidr] = 0
        q = []
        for ip in ipaddress.IPv4Network(cidr):
            host = str(ip)
            global threadCount
            while threadCount > 1000:
                sleep(0.1)
            t = Thread(target=servertest, args=(host, cidr))
            threadCount += 1
            t.start()
            q.append(t)
        
        for t in q:
            t.join()
    
    return json.dumps(runningList)

# @api.route('/api/runningList', methods=['POST'])
# @cross_origin()
def post_runningList():
    global runningList, foundCount
    airtable = Airtable(AIRTABLE_BASE_ID, 'Scan', AIRTABLE_TOKEN)
    for host in runningList:
        save_to_found(host)
    for key in foundCount:
        # print(key, '->', foundCount[key])
        # if (foundCount[key] > 0)
        record = airtable.match('Target', key)
        
        url = f"{AIRTABLE_URL}/Scan"
        headers = {"Authorization" : "Bearer " + AIRTABLE_TOKEN, "Content-Type" : "application/json"}
        
        updated_records = {
            "records": [
                {
                    "id": record['id'],
                    "fields": {
                        "Found": foundCount[key]
                    },
                }
            ]
        }

        response = requests.request("PATCH", url, headers=headers, data=json.dumps(updated_records))
    
    return True

@api.route('/api/updateList', methods=['POST', 'GET', 'PUT', 'DELETE'])
@cross_origin()
def updateList():
    get_runningList()
    post_runningList()

    return '', 204

def main():
    response = get_scan_records()
    
    for record in response:
        # print((record.get('fields')).get('Target'))
        cidr = (record.get('fields')).get('Target')
        q = []
        for ip in ipaddress.IPv4Network(cidr):
            host = str(ip)
            t = Thread(target=servertest, args=(host, ))
            t.start()
            q.append(t)
        
        for t in q:
            t.join()

if __name__ == '__main__':
    #Check our config file
    # save_to_found("1.1.1.1")
    # main()
    # api.run() 
    api.run(host='0.0.0.0')
