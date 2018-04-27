#!/usr/bin/env python
# -*- coding: utf-8 -*-
import logging
import json
import sys
from os import environ, path, getcwd
import nmap
from time import strftime
import yaml
import re
import argparse
from collections import OrderedDict

host_groups = {}
defs = {}

parser = argparse.ArgumentParser(description='NMap based dynamic inventory')
parser.add_argument('-d', '--debug', action='store_true', help='Debug')
parser.add_argument('-j', '--json', action='store_true', help='Generate Ansible Tower dynamic inventory file.')
args = parser.parse_args()

def parse_defs():
  if not args.debug:
    defs = yaml.load(environ['DEFINITIONS'])
  else:
    defs = yaml.load(open('./definitions.yaml', 'r'))

  for os in defs:
    host_groups[os] = {'hosts': [], 'vars': {}, 'children': []}
    for group in defs[os]: 
      host_groups[group] = {'hosts': [], 'vars': {}, 'children': []}
      if 'vars' in defs[os][group]:
        host_groups[group]['vars'] = defs[os][group]['vars']
      if 'children' in defs[os][group]:
        host_groups[group]['children'] = defs[os][group]['children']
  return defs, host_groups

def genereate_inventory(host_groups):
  if not args.debug:
    ini_filepath = path.join(environ['WORKSPACE'], 'artifacts/')
  else:
    ini_filepath = getcwd()

  with open(path.join(ini_filepath, 'inventory.ini'), 'w+') as ini_file:
    print("Generating inventory in: " + ini_file.name)

    for host_group in host_groups:
      ini_file.write("[" + host_group + "]\n")
      for host in host_groups[host_group]['hosts']:
        ini_file.write(host + "\n")
      ini_file.write("\n")
      if len(host_groups[host_group]['children']) > 0:
        ini_file.write("[" + host_group + ":children]\n")
        for child in host_groups[host_group]['children']:
          ini_file.write(child + "\n")
        ini_file.write("\n")      
      if len(host_groups[host_group]['vars']) > 0:
        ini_file.write("[" + host_group + ":vars]\n")
        for key,val in host_groups[host_group]['vars'].iteritems():
          ini_file.write(key + "=" + val + "\n")
        ini_file.write("\n")

def parse_host_groups(defs, host_groups):
  for os in defs:
    for host in host_groups[os]['hosts']:
      for host_group in defs[os]:
        if len(defs[os][host_group]['pattern-match']) > 0:
          if bool(re.search(defs[os][host_group]['pattern-match'], host)):
            host_groups[host_group]['hosts'].append(host)
  return host_groups

def process_scan(record, host_groups):
  for host in record.all_hosts():
    if record[host].state() == 'up':
      if len(record[host]['osmatch']) > 0:
        if record[host].hostname() != '':
            hostname = record[host].hostname()
            osfamily = record[host]['osmatch'][0]['osclass'][0]['osfamily'].lower()
            try: 
              host_groups[osfamily]['hosts'].append(hostname)
            except Exception:
              logging.info(record[host]['addresses']['ipv4'] + ' reason: os ' + osfamily + ' is not in definitions')
              sys.exc_clear()   # pass doesn't clear an exception
        else:
          logging.info(record[host]['addresses']['ipv4'] + ' reason: no hostname detected')

      else:
          logging.info(record[host]['addresses']['ipv4'] + ' reason: no os detected')

    elif record[host].state() == 'down':
      logging.info(record[host]['addresses']['ipv4'] + ' reason: host is unreachable')

def scan_subnets(subnets):
  nm = nmap.PortScanner()
  for subnet in subnets:
    nm.scan(hosts=subnet, arguments='-v -F -O', sudo=True)
    process_scan(nm, host_groups)


def load_subnets():
  subnets = []
  if not args.debug:
    subnet_list = environ['SUBNET']
  else:
    subnet_list = '127.0.0.1'

  for record in subnet_list.splitlines():
    subnets.append(record)
  return subnets

def main():
  if not args.debug:
    log_file_path = path.join(environ['WORKSPACE'], 'artifacts/')
  else:
    log_file_path = getcwd()

  with open(path.join(log_file_path, 'unknown_hosts-' + strftime("%m%d%Y") + '.log'), 'w+') as log_file: 
    print("Logging to: " + log_file.name)
    logging.basicConfig(filename=log_file.name,level=logging.INFO, format='[%(asctime)s] %(levelname)-8s %(message)s', datefmt='%m/%d/%Y %H:%M:%S')

  print("Parsing definitions.")
  defs, host_groups = parse_defs()
  print("Loading subnets.")
  subnets = load_subnets()
  print("Scanning subnets.")
  scan_subnets(subnets)
  print("Parsing hosts.")
  host_groups = parse_host_groups(defs, host_groups)
  
  # Optional JSON output for Ansibel Tower
  if args.json:
    if not args.debug:
      json_file_path = path.join(environ['WORKSPACE'], 'artifacts/')
    else:
      json_file_path = getcwd()

    with open(path.join(json_file_path, 'output-' + strftime("%m%d%Y") + '.json'), 'w+') as out_file:
      print("Dumping JSON to: " + out_file.name)
      json.dump(host_groups, out_file)
  
  sorted_host_groups = OrderedDict(sorted(host_groups.iteritems()))

  # Inventory output
  genereate_inventory(sorted_host_groups)

if __name__ == '__main__':
  main()
