#!/usr/bin/env python3.7
## $Id$
##
## 
##
# following is pulled from enum
ftypes = ['AUPARSE_TYPE_UNCLASSIFIED',  'AUPARSE_TYPE_UID', 'AUPARSE_TYPE_GID',
          'AUPARSE_TYPE_SYSCALL', 'AUPARSE_TYPE_ARCH', 'AUPARSE_TYPE_EXIT',
          'AUPARSE_TYPE_ESCAPED', 'AUPARSE_TYPE_PERM', 'AUPARSE_TYPE_MODE',
          'AUPARSE_TYPE_SOCKADDR', 'AUPARSE_TYPE_FLAGS', 'AUPARSE_TYPE_PROMISC',
          'AUPARSE_TYPE_CAPABILITY', 'AUPARSE_TYPE_SUCCESS', 'AUPARSE_TYPE_A0',
          'AUPARSE_TYPE_A1', 'AUPARSE_TYPE_A2', 'AUPARSE_TYPE_A3', 'AUPARSE_TYPE_SIGNAL',
          'AUPARSE_TYPE_LIST', 'AUPARSE_TYPE_TTY_DATA',
          'AUPARSE_TYPE_SESSION', 'AUPARSE_TYPE_CAP_BITMAP', 'AUPARSE_TYPE_NFPROTO',
          'AUPARSE_TYPE_ICMPTYPE', 'AUPARSE_TYPE_PROTOCOL',
          'AUPARSE_TYPE_ADDR', 'AUPARSE_TYPE_PERSONALITY',
          'AUPARSE_TYPE_SECCOMP', 'AUPARSE_TYPE_OFLAG',
          'AUPARSE_TYPE_MMAP', 'AUPARSE_TYPE_MODE_SHORT', 'AUPARSE_TYPE_MAC_LABEL',
          'AUPARSE_TYPE_PROCTITLE', 'AUPARSE_TYPE_HOOK',
          'AUPARSE_TYPE_NETACTION', 'AUPARSE_TYPE_MACPROTO',
          'AUPARSE_TYPE_IOCTL_REQ', 'AUPARSE_TYPE_ESCAPED_KEY',
          'AUPARSE_TYPE_ESCAPED_FILE', 'AUPARSE_TYPE_FANOTIFY']

import semanage
import audit
import auparse

ftypemap = {}
for ftype in ftypes:
    if hasattr(auparse, ftype):
        ftypemap[getattr(auparse, ftype)] = ftype
    
from tempfile import TemporaryDirectory
from datetime import datetime
import time
import logging
import glob
import socket
import os
from jinja2 import Environment, FileSystemLoader
from pathlib import Path
import subprocess
import re
import json
import sys
import argparse

logger = logging.getLogger(__name__)

cmd = Path(sys.argv[0])
app_root = str(cmd.parent.absolute())

host = socket.gethostname()

parser = argparse.ArgumentParser(description="Manage SELinux modules")
parser.add_argument('--hostname', help="Specify hostname (default is %s)" % host,
                    default=host, action='store')
parser.add_argument('--input-directory', help="Specify input source directory for SElinux modules", default="generated", action="store")
parser.add_argument('--input-file', help="Specify audit log input for subprocess.",
                    action="store")
parser.add_argument('--search', '-s', help="Search the auditlog",
                    action="store")
args = parser.parse_args()

host = args.hostname

x = host.split('.')
x.reverse()
mod_prefix = '_'.join(x)


rules = {}

generated = Path(args.input_directory)
comment = ''
for tesrc in glob.glob("generated/%s_*.te" % mod_prefix):
    print(tesrc)
    with open(tesrc, 'r') as f:
        for l in f:
            l = l.rstrip()
            if l.startswith('#'):
                comment = l
                continue
            
            match = re.match('^allow\s+(\S+)\s+([^\s:]+):(\S+)\s+(.*);', l)#(?:\{((?:\s\S+){2,})\s\}|(\S+));$', l)
            if match:
                (source, target, class_, ops) = match.groups()
                if ops.startswith('{'):
                    j = ops[2:-2].split(' ')
                else:
                    j = [ops]

                if not source in rules:
                    rules[source] = {}
                    
                if not target in rules[source]:
                    rules[source][target] = {}

                if not class_ in rules[source][target]:
                    rules[source][target][class_] = {}

                for op in j:
                    if op in rules[source][target][class_]:
                        logger.warning("op already in %s/%s/%s/%s", source, target, class_, op)
                    else:
                        rules[source][target][class_][op] = True
                    
#                rules[source][target].append([class_, j, comment])
                comment = ''
            else:
                pass
                #print(l, file=sys.stderr)

#json.dump(rules, fp=sys.stdout, indent=4)

def mycb(aup, cb_event_type, user_data):
    if cb_event_type == auparse.AUPARSE_CB_EVENT_READY:
        if aup.first_record() < 0:
            return
        while True:
            event = aup.get_timestamp()
#            print(event.host)
#            print(str(event))
            mytype = aup.get_type_name()
#            print("Record type: %s" % mytype)
            while True:
                f = aup.get_field_name()
                t = aup.get_field_type()
                v = aup.get_field_str()
#            if f == 'node':
#                print(f, ftypes[t], v)
                if not aup.next_field(): break

            if not aup.next_record(): break

with TemporaryDirectory(None, 'mods-%s-' % mod_prefix) as tempdir:
    out = Path(tempdir)
    if not out.exists():
        print("making directory %s" % out)
        out.mkdir()
        
    os.chdir(str(out))
        

    lines = None
    #if len(sys.argv) == 1:
    ausearch_out = None
    audit_lines = []

    if args.search:
        ausearch_proc = subprocess.Popen(['/sbin/ausearch', *(args.search.split(' '))], stdout=subprocess.PIPE)
        if ausearch_proc.returncode:
            print("ausearch subprocess failed");
            exit(1)

#        ausearch_out = x.stdout.decode('utf-8')
#        audit_lines = ausearch_out.split('\n')

#    print("Audit line count: %d" % len(audit_lines))

    assert ausearch_proc.stdout
    aup = auparse.AuParser(auparse.AUSOURCE_FEED)
    aup.add_callback(mycb, 1)

    audit2allowproc = subprocess.Popen(['audit2allow'], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    ausearch_output = b""
    all_allow_out = b""
    while ausearch_proc.returncode is None:
        (stdout, stderr) = ausearch_proc.communicate()
        ausearch_output = ausearch_output + stdout
        print(stdout)
        (allow_out, allow_err) = audit2allowproc.communicate(stdout)
        all_allow_out = all_allow_out + allow_out
        
        result = aup.feed(stdout)

    aup.flush_feed()
    
    aup = None

    src = 'audit2allow'
    allow = all_allow_out.decode('utf-8')
    
    lines = allow.split('\n')
    #else:
#    with open(sys.argv[1], 'r'):

    source = None
    for line in lines:
#        if line == '#!!!! This avc is allowed in the current policy':
#            lines.pop(0)
#            continue
    
        print(line)
        match = re.match('^#=+\s(\S+)\s=', line)
        if match:
            source = match.group(1)
            continue
        match = re.match('^allow\s(\S+)\s([\S^:]+):(\S+)\s(?:\{((?:\s\S+){2,})\s\}|(\S+));$', line)
        if match:
            (source, target, class_, j1, j2) = match.groups()
            j = None
            if j1:
                j = j1.strip().split(' ')
            else:
                j = [j2]

            if not source in rules:
                rules[source] = {}

                    
            if not target in rules[source]:
                rules[source][target] = {}

            if not class_ in rules[source][target]:
                rules[source][target][class_] = {}

            for op in j:
                if op in rules[source][target][class_]:
                    logger.warning("op already in %s/%s/%s/%s", source, target, class_, op)
                else:
                    rules[source][target][class_][op] = True
            

    logger.info("initializing template with laoder dir %s", app_root)
    env = Environment(
        loader=FileSystemLoader(app_root),
        trim_blocks=True,
        lstrip_blocks=True,
        autoescape=False,
)

    for source, sdict in rules.items():
        name = source[0:-2]
        t = env.get_template('module.jinja2')
        classes = {}
        rules = []
        types = { source: True }
        for target, tdict in sdict.items():
            if not (target in types or target in ('self')):
                types[target] = True
            
            for class_ in tdict.keys():
                ops = tdict[class_].keys()
                rules.append('allow %s %s:%s { %s };' % (source, target, class_, ' '.join(ops)))
                if not class_ in classes:
                    classes[class_] = {}
                for op in ops:
                    classes[class_][op] = True

        module_name = '%s_%s' % (mod_prefix, name)

        fname = '%s.te' % module_name;
        with open(fname, 'w') as f:
            print(t.render(module_name=module_name,
                   classes=classes,
                   rules=rules,
                       types=types), file=f)

        mod_fname = '%s.mod' % module_name
        r = subprocess.run(['checkmodule', '-o', mod_fname, '-m', fname], stdout=subprocess.PIPE)
        if r.returncode:
#            print(r.stderr.decode('utf-8'), file=sys.stderr)
            exit(1)

        pp_out = '%s.pp' % module_name
        r = subprocess.run(['semodule_package', '-o', pp_out, '-m', mod_fname], stdout=subprocess.PIPE)
        if r.returncode:
#            print(r.stderr.decode('utf-8'), file=sys.stderr)
            exit(1)

    print(tempdir)
    while True:
        time.sleep(5)
    
#json.dump(rules, fp=sys.stdout, indent=4)
os.chdir(app_root)

