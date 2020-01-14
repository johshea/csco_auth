import requests
import yaml
from requests.auth import HTTPBasicAuth
import urllib3
from ncclient import manager
import xmltodict


# Silence the insecure warning due to SSL Certificate
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

#load values into a dictionary

with open(r'./env_vars.yml') as file:
    handlers = yaml.load(file, Loader=yaml.SafeLoader)


#start declaaring env variables based on handlers dictionary object
#Webex Teams
wTEAMS_TOKEN = handlers['webex_teams']['wteams-token']
#print(wteamstoken) #validate value is loaded

#Meraki Dashboard API
mDASH_TOKEN = handlers['meraki_dashboard']['meraki-api-key']
#print (dashboard_key) #validate value is loaded

#Webex Teams REST Headers
def wtheaders():
    wtheaders = {
       'Authorization': "Bearer {{wTEAMS_TOKEN}}",
       'Content-Type': "application/json",
       'cache-control': "no-cache",
                }
    return wtheaders

#Umbrella REST Headers
def uheaders():
    uheaders = {
       'Authorization': handlers['umbrella']['umbrella-auth-type'] + " " + handlers['umbrella']['umbrella-api-key'],
       'cache-control': "no-cache",
               }
        #print(uheaders)

    return uheaders

#Meraki REST Headers
def mheaders():
    mheaders = {
        'x-cisco-meraki-api-key': format(str(handlers['meraki_dashboard']['meraki-api-key'])),
        'Content-Type': 'application/json'
         }
    #print(mheaders)

#Functions for services requiring complex auth
#pull DNAC token and return
def get_dnacauth_token():
    """
    Building out Auth request. Using requests.post to make a call to the Auth Endpoint
    """
    url = handlers['dnac']['dnac_url']  # Endpoint URL
    resp = requests.post(url, auth=HTTPBasicAuth(handlers['dnac']['dnac_username'], handlers['dnac']['dnac_password']))
    DNAC_TOKEN = resp.json()['Token']
    if DNAC_TOKEN == None:
        dnacheaders = "token not found or not available at this time"

    if DNAC_TOKEN != None:
        dnacheaders = {
            'x-auth-access-token': format(str(DNAC_TOKEN)),
            'Content-Type': 'application/json'
        }

    return dnacheaders

#pull FMC token and return headers
def get_fmcauth_token():
    url = handlers['fmc']['fmc_baseurl'] + handlers['fmc']['fmc_gettoken_url']
    resp = requests.post(url, auth=HTTPBasicAuth(handlers['fmc']['fmc_username'], handlers['fmc']['fmc_password']), verify=False)
    auth_headers = resp.headers
    FMC_TOKEN = auth_headers.get('X-auth-access-token', default=None)

    fmcheaders = {
        'x-auth-access-token': format(str(FMC_TOKEN)),
        'Content-Type': 'application/json'
            }

    return fmcheaders

#Pull Vmanage Cookie and return
def get_vmanage_cookie():
    url = handlers['csdwan']['sdwan_url']
    #print(url) #use to validate information
    #headers = {'Content-Type':  handlers['csdwan']['sdwan_encoding']}
    #print(headers)
    auth_vars = {'j_username': handlers['csdwan']['sdwan_username'], 'j_password': handlers['csdwan']['sdwan_password']}
    #print(login_data)
    auth_session = requests.session()
    resp = auth_session.post(url, data=auth_vars, verify=False)
    #print(resp.content)

    if b'<html>' in resp.content:
        print('login Failed')
        sys.exit(0)

    return

#CLI auth with Paramiko
def paramiko_auth(host):
#from call point include a host fqdn or ip
    connect_params = {
        "host": host,
        "port": handlers['paramiko']['paramiko_port'],
        "username": handlers['paramiko']['paramiko_username'],
        "password": handlers['paramiko']['paramiko_password'],
        "hostkey_verify": False,
        "look_for_keys": False,
        "device_params": {"name": "nexus"},
                    }
    return connect_params