import json
import re
import time
from multiprocessing import JoinableQueue, Process, Queue
from os import geteuid, getpid, mkdir, path
from subprocess import check_output

import ldap
import nmap
import yaml
from ldap.controls import SimplePagedResultsControl


class parallel_nmap:
    # # Example usage
    # p = parallel_nmap(subnets=['127.0.0.1', '0.0.0.0', '127.0.0.2'])
    # print p.process_subnets()
    hosts = None
    results = None

    def __init__(self, num_workers=2, hosts=[]):
        """
        num_workers = number of worker threads
        subnets[] = initial subnets to scan
        """
        self.results = Queue()
        self.hosts = JoinableQueue()
        for item in hosts:
            self.add_host_to_scan(item)
        self.processes = [Process(target=self.scan) for i in range(num_workers)]
        print "Starting %d workers" % num_workers
        for p in self.processes:
            p.start()

    def add_host_to_scan(self, item):
        """Add hoost to scanning queue"""
        # print "Adding %s to queue" % item
        self.hosts.put(item)

    def scan(self):
        """Actual scan. Runs on each process until queue is empty"""
        # print "[%d] Starting worker" % getpid()
        while True:
            item = self.hosts.get()
            if item is None:
                print "[%d] No more work" % getpid()
                break

            # Actually do the scan here
            print "[%d] Scanning: %s" % (getpid(), item)
            nm = nmap.PortScanner()
            nm.scan(hosts=item,
                    arguments='-v -F -O',
                    sudo=(geteuid() != 0))
            self.results.put(nm._scan_result['scan'])
            print "[%d] Finished: %s" % (getpid(), item)
            self.hosts.task_done()

    def process_hosts(self):
        """Processes scan results and returns single dictionary item"""
        output_dict = {}
        while True:
            item = self.results.get()

            # kill everything if we hit the guard since we're done
            if item == "DONE":
                print "Done scanning"
                for p in self.processes:
                    # print "[%d] Terminating worker" % p.pid
                    p.terminate()
                break

            # merge result to output_dict
            output_dict.update(item)

            # insert guard to result queue if work completed
            if self.hosts.empty():
                self.hosts.join()
                self.results.put("DONE")

        return output_dict


def get_ad_hosts():
    """Return list of (host, OS) tuples from Active Directory"""
    # Service account running the ldap queries
    DN = 'REPLACE_ME: Domain Name ie: test.example.com'
    secret = 'REPLACE_ME: Password/token to log into AD'

    # LDAP server information and constants
    server = "REPLACE_ME: Domain Controller ie: ldap://test.example.com"
    base = "REPLACE_ME: Reduces search tree ie: dc=test,dc=example,dc=com"
    scope = ldap.SCOPE_SUBTREE

    # Create LDAP server bind
    ld = ldap.initialize(server)
    ld.protocol_version = 3
    ld.set_option(ldap.OPT_REFERRALS, 0)
    ld.simple_bind_s(DN, secret)

    # Get computers that AD knows about
    group_filter = "(objectClass=computer)"
    group_attrs = ["dNSHostName", "operatingSystem"]

    # Setup pagination for large result sets
    page_size = 1000
    lc = SimplePagedResultsControl(criticality=True, size=page_size, cookie='')
    msgid = ld.search_ext(base, scope, group_filter, group_attrs, serverctrls=[lc])

    results = []
    while True:
        rtype, rdata, rmsgid, serverctrls = ld.result3(msgid)
        # Strip out comments and domain redirects
        raw_results = [item[1] for item in rdata if isinstance(item[1], dict)]
        # Strip items without hostnames
        results.extend([item for item in raw_results if 'dNSHostName' in item.keys()])
        pctrls = [c for c in serverctrls]
        if pctrls:
            cookie = pctrls[0].cookie
            if cookie:
                lc.cookie = cookie
                msgid = ld.search_ext(base, scope, group_filter, group_attrs, serverctrls=[lc])
            else:
                break
        else:
            break

    output = []
    for hostos_dict in results:
        output_host = hostos_dict['dNSHostName'][0]
        if 'operatingSystem' in hostos_dict.keys():
            output_os = hostos_dict['operatingSystem'][0]
        else:
            output_os = ''
        output.append((output_host, output_os))

    print 'Found %d hosts in Active Directory' % len(output)

    return output


def generate_inventory(conf, hostos_list):
    """Create inventory file"""
    inventory_fn = path.join(conf['config']['artifact-dir'],
                             conf['config']['inventory-file'])
    host_groups = conf['host-groups']
    blacklist = conf['blacklist']
    os_list = conf['os-list']

    for group, data in host_groups.iteritems():
        tentative_hosts = set()
        if 'pattern-match' in data.keys():
            for host, os in hostos_list:
                # Blacklist check
                for blacklisted in blacklist:
                    if bool(re.search(blacklisted, host)):
                        continue
                    else:
                        # OS check
                        if 'os' in data.keys():
                            acceptable_os = []
                            for os_def in data['os']:
                                acceptable_os.extend(os_list[os_def])
                            if os not in acceptable_os:
                                continue

                        # Actual pattern/os matching happens here
                        if bool(re.search(data['pattern-match'], host)):
                            tentative_hosts.add(host)

        # Only groups that have host matches will populate
        if len(tentative_hosts) > 0:
            data['hosts'] = sorted(tentative_hosts)

    with open(inventory_fn, 'w+') as i_file:
        for group in sorted(host_groups.keys()):
            data = host_groups[group]
            i_file.write('[%s]\n' % group)
            if 'hosts' in data.keys():
                for host in data['hosts']:
                    i_file.write('%s\n' % host)
                i_file.write('\n')
            if 'children' in data.keys():
                i_file.write('[%s:children]\n' % group)
                for child in data['children']:
                    i_file.write('%s\n' % child)
                i_file.write('\n')
            if 'vars' in data.keys():
                i_file.write('[%s:vars]\n' % group)
                for var, value in data['vars'].iteritems():
                    i_file.write('%s=%s\n' % (var, value))
                i_file.write('\n')

    return host_groups


def pingsweep(conf):
    """Return (host, '') tuples from nmap sweep since no OS scanning here.
    Will not return hosts that are down or have no hostname."""
    # nmap-options: '-v -sn'
    subnets = conf['pingsweep-subnets']
    ping_raw_fn = path.join(conf['config']['artifact-dir'],
                            conf['config']['ping-raw-file'])

    print 'Pingsweeping subnet(s): %s' % ', '.join(subnets)
    print '...'
    nm = nmap.PortScanner()
    start = time.time()
    nm.scan(hosts=' '.join(subnets), arguments='-v -sn')
    print 'Scanned %d hosts in %.2f seconds in pingsweep' % (len(nm.all_hosts()), time.time() - start)

    up_host = [(x, nm[x]['hostnames'][0]['name']) for x in nm.all_hosts() if nm[x]['status']['state'] != 'down']
    have_hostname = [x for x in up_host if x[1] != '']
    print 'Found %d live hosts with hostnames in pingsweep' % len(have_hostname)

    output = [(x[1], '') for x in have_hostname]

    with open(ping_raw_fn, 'w+') as ping_file:
        json.dump(output, ping_file)

    return output


def compare_and_fill(conf, source_list, check_list):
    """Compare two (host, OS) lists and get missing OS info for unique hosts"""
    nmap_raw_fn = path.join(conf['config']['artifact-dir'],
                            conf['config']['nmap-raw-file'])

    source_hostnames = {x[0] for x in source_list}
    hosts_to_scan = [x[0] for x in check_list if x[0] not in source_hostnames and x[1] == '']
    if len(hosts_to_scan) > 0:
        print 'Scanning %d hosts for OS\n...' % len(hosts_to_scan)

        # # Non parallel nmap OS scan
        # nm = nmap.PortScanner()
        # should_we_sudo = (geteuid() != 0)
        # start = time.time()
        # nm.scan(hosts=' '.join(hosts_to_scan), arguments='-v -F -O', sudo=should_we_sudo)
        # print 'Scanned %d hosts for OS in %.2f seconds' % (len(hosts_to_scan), time.time() - start)
        #
        # with open(nmap_raw_fn, 'w+') as nmap_file:
        #     json.dump(nm._scan_result['scan'], nmap_file)
        #
        # up_host = [(nm[x]['hostnames'][0]['name'], nm[x]['osmatch'])
        #           for x in nm.all_hosts() if nm[x]['status']['state'] != 'down']
        # output = [(x[0], x[1][0]['osclass'][0]['osfamily']) for x in up_host if len(x[1]) > 0]

        # Parallel nmap OS scan
        start = time.time()
        p = parallel_nmap(hosts=hosts_to_scan, num_workers=10)
        data = p.process_hosts()
        print 'Scanned %d hosts for OS in %.2f seconds' % (len(hosts_to_scan), time.time() - start)

        with open(nmap_raw_fn, 'w+') as nmap_file:
            json.dump(data, nmap_file)

        up_host = [(data[x]['hostnames'][0]['name'], data[x]['osmatch'])
                   for x in data.keys() if data[x]['status']['state'] != 'down']
        output = [(x[0], x[1][0]['osclass'][0]['osfamily']) for x in up_host if len(x[1]) > 0]
        print 'Found %d live hosts in nMap OS scan' % len(output)

        return output
    else:
        return []


def generate_known_hosts(conf, hosts):
    """Create known_hosts file"""
    ssh_thumb_fn = path.join(conf['config']['artifact-dir'],
                             conf['config']['ssh-thumb-file'])

    # We want somethig like:
    # ssh-keyscan -t ssh-rsa -f - <<< server1.test.example.com server2.test.example.com
    start = time.time()
    r = check_output(args='ssh-keyscan -t ssh-rsa -f - <<< %s' % ' '.join(hosts), executable='/bin/bash', shell=True)
    end = time.time()
    print 'Scanning %d hosts for keys took %.2f second(s)' % (len(hosts), end-start)

    with open(ssh_thumb_fn, 'w+') as ssh_file:
        ssh_file.write(r)


if __name__ == '__main__':
    config = yaml.load(open('definitions.yaml', 'r'))
    host_os_list = []

    if not path.exists(config['config']['artifact-dir']):
        mkdir(config['config']['artifact-dir'])

    # Get hosts from AD
    host_os_list.extend(get_ad_hosts())

    # Get pingsweep host list
    nmap_host_list = pingsweep(config)

    # Concat completed nmap scan and AD scan
    host_os_list.extend(compare_and_fill(config, host_os_list, nmap_host_list))

    # Generate inventory and dump known_hosts fingerprints
    all_data = generate_inventory(config, host_os_list)
    generate_known_hosts(config, all_data['linux']['hosts'])
