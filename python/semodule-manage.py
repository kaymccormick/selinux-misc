#!/usr/bin/python3

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
args = parser.parse_args()

host = args.hostname

x = host.split('.')
x.reverse()
mod_prefix = '_'.join(x)


rules = {}

generated = Path('generated')
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

with TemporaryDirectory(None, 'mods-%s-' % mod_prefix) as tempdir:
    out = Path(tempdir)
    if not out.exists():
        print("making directory %s" % out)
        out.mkdir()
        
    os.chdir(str(out))
        

    lines = None
    #if len(sys.argv) == 1:
    src = 'audit2allow'
    if len(sys.argv) > 1:
        x = subprocess.run(['audit2allow', '-i', sys.argv[1]], stdout=subprocess.PIPE)
    else:
        x = subprocess.run(['audit2allow', '-b'], stdout=subprocess.PIPE)
    
    if x.returncode:
        print(x.stderr.decode('utf-8'), file=sys.stderr)
        exit(1)
    
    allow = x.stdout.decode('utf-8')
    lines = allow.split('\n')
    #else:
#    with open(sys.argv[1], 'r'):
        

    source = None
    for line in lines:
        if line == '#!!!! This avc is allowed in the current policy':
            lines.pop(0)
            continue
    
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
            print(r.stderr.decode('utf-8'), file=sys.stderr)
            exit(1)

        pp_out = '%s.pp' % module_name
        r = subprocess.run(['semodule_package', '-o', pp_out, '-m', mod_fname], stdout=subprocess.PIPE)
        if r.returncode:
            print(r.stderr.decode('utf-8'), file=sys.stderr)
            exit(1)

    print(tempdir)
    while True:
        time.sleep(5)
    
#json.dump(rules, fp=sys.stdout, indent=4)
os.chdir(app_root)

