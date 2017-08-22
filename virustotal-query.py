import json
import requests
import time

urls_out = {}
urls_out['urls'] = []

try:
	with open('urllist.json') as outfile:
		urls_out = json.load(outfile)
except ValueError, error:  # includes JSONDecodeError                          
	logger.error(error)                                                           
return None 

urlfile = "urls.txt"

with open (urlfile, 'r') as infile:
	data = infile.read()
url_list = data.splitlines()

for url in url_list:
	headers = {
  	"Accept-Encoding": "gzip, deflate",
 	 "User-Agent" : "gzip,  My Python requests library example client or username"
	  }
	params = {'apikey': 'apikeygoeshere', 'resource':url}
	response = requests.post('https://www.virustotal.com/vtapi/v2/url/report',
	  params=params, headers=headers)
	json_response = response.json()

	#print json.dumps(json_response, sort_keys=False, indent=4)
	url_response = json_response["url"]
	positives_response = json_response["positives"]
	total_response = json_response["total"]
	scandate_response = json_response["scan_date"]
	print url_response, positives_response, total_response, scandate_response
	urls_out['urls'].append({'url': url_response, 'scan':{'scandate': scandate_response,'positives': positives_response,'total': total_response}})
	#urls_out['urls'].append({'url': url_response,'scandate': scandate_response,'positives': positives_response,'total': total_response})
	#urls_out['urls'].append({'url': url_response,'scandate': scandate_response,'positives': positives_response,'total': total_response})
	time.sleep(15)

	with open('urllist.json', 'w') as outfile:
		json.dump(urls_out, outfile, indent=4)
