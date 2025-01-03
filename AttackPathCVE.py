#!/usr/bin/env python3
import http.client
import json
import csv
import argparse
from urllib.parse import urlencode
from datetime import datetime
import config
import os

def clean_url(url):
   return url.replace('https://', '').replace('http://', '').rstrip('/')

# we are doing this proxy handling manually because of the limitation of not wanting to pip install additional pkgs
def get_proxy_settings():
   https_proxy = os.environ.get('HTTPS_PROXY') or os.environ.get('https_proxy')
   if https_proxy:
       https_proxy = https_proxy.replace('https://', '').replace('http://', '')
       if ':' in https_proxy:
           proxy_host, proxy_port = https_proxy.split(':')
           proxy_port = int(proxy_port)
           print(f"Using proxy: {proxy_host}:{proxy_port}")
           return proxy_host, proxy_port
   return None, None

def create_connection(url, timeout=10):
   proxy_host, proxy_port = get_proxy_settings()
   if proxy_host and proxy_port:
       conn = http.client.HTTPSConnection(proxy_host, proxy_port, timeout=timeout)
       conn.set_tunnel(url)
   else:
       conn = http.client.HTTPSConnection(url, timeout=timeout)
   return conn

def login(url, api_key, api_secret):
   clean_base_url = clean_url(url)
   print(f"Attempting login to {clean_base_url}...")
   try:
       conn = create_connection(clean_base_url)
       payload = json.dumps({
           "username": api_key,
           "password": api_secret
       })
       headers = {
           'Content-Type': 'application/json; charset=UTF-8',
           'Accept': 'application/json; charset=UTF-8'
       }
       
       conn.request("POST", "/login", payload, headers)
       response = conn.getresponse()
       if response.status == 200:
           print("Login successful!")
           return response.read().decode('utf-8')
       else:
           print(f"Login failed with HTTP status code: {response.status}")
           print(f"Response: {response.read().decode('utf-8')}")
           raise Exception(f"Login failed with status code {response.status}")
   except TimeoutError:
       print("Connection timed out. Please check:")
       print("- Network connectivity")
       print("- Proxy settings (if using corporate network)")
       print("- URL in config file")
       print(f"Current URL being used: {clean_base_url}")
       raise
   except Exception as e:
       print(f"Connection error: {str(e)}")
       raise

def get_alerts(params, headers):
   print("\nFetching attack path alerts...")
   clean_base_url = clean_url(config.url)
   try:
       conn = create_connection(clean_base_url)
       query_string = urlencode(params)
       endpoint = f"/alert?{query_string}"
       
       conn.request("GET", endpoint, '', headers)
       res = conn.getresponse()
       if res.status != 200:
           print(f"Failed to fetch alerts. Status code: {res.status}")
           print(f"Response: {res.read().decode('utf-8')}")
           raise Exception("Failed to fetch alerts")
       data = res.read()
       return json.loads(data.decode("utf-8"))
   except Exception as e:
       print(f"Error fetching alerts: {str(e)}")
       raise

def get_alert_details(alert_id, headers):
   clean_base_url = clean_url(config.url)
   try:
       conn = create_connection(clean_base_url)
       endpoint = f"/alert/{alert_id}?detailed=false&withAlertRuleInfo=false"
       
       conn.request("GET", endpoint, '', headers)
       res = conn.getresponse()
       if res.status != 200:
           print(f"Failed to fetch alert details. Status code: {res.status}")
           print(f"Response: {res.read().decode('utf-8')}")
           raise Exception("Failed to fetch alert details")
       data = res.read()
       return json.loads(data.decode("utf-8"))
   except Exception as e:
       print(f"Error fetching alert details: {str(e)}")
       raise

def extract_cves(detail):
   try:
       nodes = detail.get("metadata", {}).get("attackPathDetails", {}).get("graph", {}).get("nodes", {})
       cves = []
       for node_id, node_info in nodes.items():
           if node_info.get("nodeType") == "vulnerability":
               cves.append({
                   "id": node_id,
                   "severity": node_info.get("severity", "N/A"),
                   "cvss_score": node_info.get("cvssScore", "N/A")
               })
       return cves
   except Exception as e:
       print(f"Error extracting CVEs: {e}")
       return []

def main():
   parser = argparse.ArgumentParser(description='Fetch Prisma Cloud attack path alerts')
   parser.add_argument('months', nargs='?', type=int, default=12,
                      help='Number of months to check (default: 12)')
   args = parser.parse_args()

   try:
       auth_response = login(config.url, config.api_key, config.api_secret)
       response = json.loads(auth_response)
       JWTtoken = response["token"]
       
       headers = {
           'Accept': '*/*',
           'x-redlock-auth': JWTtoken
       }
   except Exception as e:
       print(f"Authentication failed: {e}")
       return

   initial_params = {
       'timeType': 'relative',
       'timeAmount': str(args.months),
       'timeUnit': 'month',
       'detailed': 'true',
       'policy.type': "attack_path"
   }

   try:
       attack_path_alerts = get_alerts(initial_params, headers)
       alert_details = []
       resources_without_cves = []

       for alert in attack_path_alerts:
           if "id" not in alert:
               continue
               
           attack_path_id = alert["id"]
           detail = get_alert_details(attack_path_id, headers)
           cves = extract_cves(detail)
           
           if "resource" in detail:
               resource = detail["resource"]
               resource_name = resource.get("name", "N/A")
               
               if not cves:
                   resources_without_cves.append(resource_name)
                   continue
                   
               alert_info = {
                   "resource_name": resource_name,
                   "resource_id": resource.get("id", "N/A"),
                   "attack_path_id": attack_path_id,
                   "account_id": resource.get("accountId", "N/A"),
                   "cloud_type": resource.get("cloudType", "N/A"),
                   "region": resource.get("region", "N/A"),
                   "resource_type": resource.get("resourceType", "N/A"),
                   "cves": cves
               }
               alert_details.append(alert_info)

       timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
       csv_filename = f"prisma_attack_paths_{timestamp}.csv"

       with open(csv_filename, 'w', newline='') as csvfile:
           csvwriter = csv.writer(csvfile)
           csvwriter.writerow([
               'Resource Name', 
               'Resource ID', 
               'Attack Path ID', 
               'Account ID',
               'Cloud Type',
               'Region',
               'Resource Type',
               'CVE ID',
               'CVE Severity',
               'CVSS Score'
           ])
           
           for detail in alert_details:
               for cve in detail["cves"]:
                   csvwriter.writerow([
                       detail["resource_name"],
                       detail["resource_id"],
                       detail["attack_path_id"],
                       detail["account_id"],
                       detail["cloud_type"],
                       detail["region"],
                       detail["resource_type"],
                       cve["id"],
                       cve["severity"],
                       cve["cvss_score"]
                   ])

       print("\nAttack Path Alert Summary:")
       print("==========================")

       for detail in alert_details:
           print(f"\nResource: {detail['resource_name']}")
           print(f"Resource ID: {detail['resource_id']}")
           print(f"Attack Path ID: {detail['attack_path_id']}")
           print(f"Account ID: {detail['account_id']}")
           print(f"Cloud Type: {detail['cloud_type']}")
           print(f"Region: {detail['region']}")
           print(f"Resource Type: {detail['resource_type']}")
           print("CVEs:")
           for cve in detail["cves"]:
               print(f"  - {cve['id']} (Severity: {cve['severity']}, CVSS: {cve['cvss_score']})")
           print()

       print(f"\nResources without CVEs ({len(resources_without_cves)}):")
       print("======================================")
       for resource in resources_without_cves:
           print(f"- {resource}")

       print(f"\nTotal resources with CVEs: {len(alert_details)}")
       print(f"Total resources without CVEs: {len(resources_without_cves)}")
       print(f"\nCSV file has been created: {csv_filename}")

   except Exception as e:
       print(f"An error occurred while processing alerts: {str(e)}")

if __name__ == "__main__":
   main()