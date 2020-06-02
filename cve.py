#!/usr/bin/env python3

import requests
import argparse
from collections import OrderedDict
from operator import getitem

parser = argparse.ArgumentParser(description='Get CVSSv3 score from NIST for a list of CVEs')
parser.add_argument('filename', help='File that contains comma separated values of CVE ids')
args = parser.parse_args()

f = open(args.filename,"r")
cves = map(str.strip, f.readline().split(','))
nist_api_url='https://services.nvd.nist.gov/rest/json/cve/1.0/'

extract = dict()

for cve in cves:
    #print(f"Getting {cve} info...")
    r = requests.get(url = nist_api_url + cve)
    #print(f"Done.")
    data = r.json()
    base_score = data['result']['CVE_Items'][0]['impact']['baseMetricV3']['cvssV3']['baseScore']
    vectorString = data['result']['CVE_Items'][0]['impact']['baseMetricV3']['cvssV3']['vectorString']
    extract[cve] = {"score" :base_score, "vector" : vectorString}

# Let' order the results by the CVSS score DESC
res = OrderedDict(sorted(extract.items(), key = lambda x: getitem(x[1], 'score' ), reverse=True))
for key in res:
    print(f"{key}:\t{res[key]['score']} - {res[key]['vector']}")
