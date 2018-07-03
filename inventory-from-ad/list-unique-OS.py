import re
import urllib

import ldap
from ldap.controls import SimplePagedResultsControl

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

os_list = [i['operatingSystem'][0] for i in results if 'operatingSystem' in i.keys()]

# Get NMAP unique OS families
url = 'https://svn.nmap.org/nmap/nmap-os-db'
f = urllib.urlopen(url)
nmap_db = f.read()
re_families = re.findall('\|\ (.*)\ \|.*\|', nmap_db)

os_list.extend(re_families)
os_list = sorted(set(os_list))

print 'Unique operatingSystem values:'
for os in os_list:
    print os
