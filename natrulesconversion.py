import json
import requests
import os.path
import getpass
import urllib3
import logging

#handles getting credentials, logging in and api calls
#functions to import authenticate, api_post
#from header import authenticate, api_post

logging.basicConfig(format='%(message)s',
                filename='logs.log',
                filemode='w',
                level=logging.INFO)

#disable warning about insecure web call Check Point has self signed cert
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def api_post(cred, request, json_data):
    '''Post request to checkpoints API using requests
    cred is a dictonary with all the credentials
    json_data is python dictionary with body data
    returns data and http response code'''
    
    url = "https://" + cred["ip"] + ":" + str(cred["port"]) + "/web_api/" + request
    request_headers = {"Content-Type" : "application/json", "X-chkp-sid" : cred["sid"]}
        
    response = requests.post(url,data=json.dumps(json_data), headers=request_headers, verify=False)
    code = response.status_code
    data = json.loads(response.content)
    
    #check that response was good and logging
    if code == 200:
        logging.info("API Call. Command: " + request + " Code: " + str(code))
    else:
        logging.error("API Call. Command: " + request + " Code: " + str(code))
        logging.info(json_data)
        logging.info(data)
    
    return data, code
    
def login(cred):
    '''Login to managment server and return credentials with sid'''
    
    url = "https://" + cred["ip"] + ":" + str(cred["port"]) + "/web_api/login"
    request_headers = {"Content-Type" : "application/json"}
    payload = {"user": cred["user"], "password": cred["password"]}
    
    data = requests.post(url,data=json.dumps(payload), headers=request_headers, verify=False)
    code = data.status_code
    
    try:
        data = data.json()
    except:
        print("error exiting... is API enabled on Mangement station?")
        exit()
    
    #if sucessful log, update sid and return
    if code == 200:
        logging.info("Login to " + cred["ip"] + " with user " + cred["user"])
        logging.info("API Call. Command: login Code: " + str(code))
        cred["sid"] = data["sid"]
        return cred
    #if not sucessful log and exit
    else:
        logging.info("Attempted to login to " + cred["ip"] + " with user " + cred["user"])
        logging.error("API Call. Command: login Code: " + str(code))
        print("Error authenticating to managment server. Exiting...")
        exit()
    
def get_credentials():
    '''Handles getting credentials from user
    Stores credentials in json in credentials.json
    Returns credentials as dictionary'''
    
    if os.path.isfile("credentials.json"):
        json_file = open("credentials.json").read()
        cred = json.loads(json_file)
    else:
        cred = new_site()
    
    response = print_site(cred)
    
    while response not in ["y", "Y", "7"]:
        if response.lower() == "z":
            exit()
        else:
            print("What would you like to change:")
            print("1: Connect to new site")
            print("2: Change managment IP")
            print("3: Change username")
            print("4: Change password")
            print("5: Show password")
            print("6: Change port")
            print("7: Continue")
            
            response = input("Enter selection: ")
            print("")
            
        if response == "7":
            continue
        elif response == "1":
            cred = new_site()
        elif response == "2":
            newip = input("Enter new managment IP: ")
            cred = edit_site("ip", newip, cred)
        elif response == "3":
            newuser = input("Enter new username: ")
            cred = edit_site("user", newuser, cred)
        elif response == "4":
            newpass = getpass.getpass("Enter new password: ")
            cred = edit_site("password", newpass, cred)
        elif response == "5":
            print(cred["password"])
        elif response == "6":
            newport = input("Enter new port: ")
            cred = edit_site("port", newport, cred)
        
        response = print_site(cred)
    
    return cred
            
def edit_site(key, value, cred):
    '''Edit one value of the site and update credentials.json
    Takes old cred and returns updated creds'''
    
    cred[key] = value
    json_file = open("credentials.json","w")
    json_file.write(json.dumps(cred, indent = 4))
    json_file.close()
    
    return cred
       
def print_site(cred):
    '''Prints the site that you will connect to with credentials
    Returns response if they want to connect or not
    Requires credentials of site in dictonary format'''
    
    print("")
    print("Authenticating to Managment with following credentials:")
    print("Managment server IP " + cred["ip"])
    print("Username " + cred["user"])
    print("Password ", end ='')
    for i in range(len(cred["password"])):
        print("*",end = '')
    print('')
    print("Port " + str(cred["port"]), end = "\n\n")
    
    response = input("Enter 'y' to continue, 'n' to change values and 'z' to quit: ")
    return response
    
def new_site():
    '''Walks user through entering new site credentials
    Writes new site credentials to file
    Returns new site credentials as dictionary'''
    
    cred = {}
    cred["ip"] = input("Enter managment server IP address: ")
    cred["user"] = input("Enter username: ")
    cred["password"] = getpass.getpass("Enter password: ")
    print("Press enter for default port: 443")
    port = input("Enter port number: ")
    if port == "":
        cred["port"] = 443
    else:
        cred["port"] = port
            
    json_file = open("credentials.json","w")
    json_file.write(json.dumps(cred, indent = 4))
    json_file.close()
    
    return cred    

def authenticate():
    '''Simple function that combines get_credentials
    and login to login for the first time
    Use this function in main python code
    returns credentials with sid'''
    
    cred = get_credentials()
    cred = login(cred)
    
    return cred
    
def main():
    cred = authenticate()
    natRules = api_post(cred, "show-nat-rulebase", {"details-level":"standard","use-object-dictionary": True,"package":"HomePolicy"})
    lookup = natRules[0]["objects-dictionary"]
    print()
    for element in natRules[0]["rulebase"]:
        for rule in element["rulebase"]:
            try:    
                print("Rule Number: "+str(rule["rule-number"]), end=' ')
            except:
                pass
            
            keyList = ["original-source","original-destination","translated-source","translated-destination"]
            
            for key in keyList:
                try:
                    if next(item for item in lookup if item["uid"] == str(rule[key]))["type"] == "host":
                        print("| "+key+": "+next(item for item in lookup if item["uid"] == str(rule[key]))["ipv4-address"], end="\t")
                    elif next(item for item in lookup if item["uid"] == str(rule[key]))["type"] == "network":
                        print("| "+key+": "+next(item for item in lookup if item["uid"] == str(rule[key]))["subnet4"], end="\t")
                    elif next(item for item in lookup if item["uid"] == str(rule[key]))["type"] == "CpmiAnyObject":
                        print("| "+key+": Any     ", end="\t")
                    else:
                        print("| "+key+": "+next(item for item in lookup if item["uid"] == str(rule[key]))["name"], end="    \t")
                except Exception as e:
                    print(e)
                
            print()

    return

if __name__ == "__main__":
    main()