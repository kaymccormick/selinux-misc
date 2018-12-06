#!/usr/bin/python3
## File: semodule-manage.py
## Author: Kay McCormick
##
## Error handling was kinda gutted, it should be replaced.
## This tool is also dependent upon the start location. Should be fixed.
##
## following is pulled from enum, could probably use a regexp.
ftypes=['AUPARSE_TYPE_UNCLASSIFIED','AUPARSE_TYPE_UID','AUPARSE_TYPE_GID','AUPARSE_TYPE_SYSCALL','AUPARSE_TYPE_ARCH','AUPARSE_TYPE_EXIT','AUPARSE_TYPE_ESCAPED','AUPARSE_TYPE_PERM','AUPARSE_TYPE_MODE','AUPARSE_TYPE_SOCKADDR','AUPARSE_TYPE_FLAGS','AUPARSE_TYPE_PROMISC','AUPARSE_TYPE_CAPABILITY','AUPARSE_TYPE_SUCCESS','AUPARSE_TYPE_A0','AUPARSE_TYPE_A1','AUPARSE_TYPE_A2','AUPARSE_TYPE_A3','AUPARSE_TYPE_SIGNAL','AUPARSE_TYPE_LIST','AUPARSE_TYPE_TTY_DATA','AUPARSE_TYPE_SESSION','AUPARSE_TYPE_CAP_BITMAP','AUPARSE_TYPE_NFPROTO','AUPARSE_TYPE_ICMPTYPE','AUPARSE_TYPE_PROTOCOL','AUPARSE_TYPE_ADDR','AUPARSE_TYPE_PERSONALITY','AUPARSE_TYPE_SECCOMP','AUPARSE_TYPE_OFLAG','AUPARSE_TYPE_MMAP','AUPARSE_TYPE_MODE_SHORT','AUPARSE_TYPE_MAC_LABEL','AUPARSE_TYPE_PROCTITLE','AUPARSE_TYPE_HOOK','AUPARSE_TYPE_NETACTION','AUPARSE_TYPE_MACPROTO','AUPARSE_TYPE_IOCTL_REQ','AUPARSE_TYPE_ESCAPED_KEY','AUPARSE_TYPE_ESCAPED_FILE','AUPARSE_TYPE_FANOTIFY']

import sqlite3
import shutil
from git import Repo
import semanage
import audit
import auparse
import sepolgen.policygen as policygen
import sepolgen.defaults as defaults
import sepolgen.interfaces as interfaces
import sepolgen.objectmodel as objectmodel
import sepolicy

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
import logging.config

from yaml import load, dump

import parse


x = sepolicy.gen_bool_dict()
out = {}
for k in x:
    (module, default, desc) = x[k]
    if module not in out:
        out[module] = {}
    out[module][k] = [desc, default]#list(dict(name=k, module=module, default=default, desc=desc).values())
          
output = dump(out,default_flow_style=False)

# this doesnt work for wahtever reason
logging_config = dict(version=1,
                      loggers=dict(root=dict(level='DEBUG', handlers=['console'])),
                      formatters=dict(generic=dict(format='%(asctime)s %(levelname)-5.5s [%(name)s:%(lineno)s][%(threadName)s] %(message)s')),
                      handlers=dict(console={'class': 'logging.StreamHandler',
                                             'level': 'DEBUG',
                                             'stream': 'ext://sys.stdout',
                                             'formatter': 'generic'}),
                      
                      )
logging.config.dictConfig(logging_config)

def process_line(rules, l):
    l = l.rstrip()
    if l.startswith('#'):
        comment = l
        return

    match = re.match('^\s*(\S+)\s*\(\s*([^,\)]+)', l)
    if match:
        (iface, arg) = match.groups()
        rest = l[match.end():]
        json.dump(dict(iface=iface,arg1=arg,rest=rest), fp=sys.stderr, indent=4)
        print("", file=sys.stderr)
        if iface != "policy_module":
            print(l, file=sys.stderr)
            logger.warning("iface = %s, arg1 = %s" % (iface, arg))
            rules.source(arg).add_iface_call(l)
        
    match = re.match('^allow\s+(\S+)\s+([^\s:]+):(\S+)\s+(.*);', l)#(?:\{((?:\s\S+){2,})\s\}|(\S+));$', l)
    if match:
        (source, target, class_, ops) = match.groups()
        if ops.startswith('{'):
            j = ops[2:-2].split(' ')
        else:
            j = [ops]


        class_rules = rules.source(source).target(target).class_(class_)
        
        for op in j:
            if class_rules.has_op(op):
                logger.warning("op already in %s/%s/%s/%s", source, target, class_, op)
            else:
                class_rules.has_op(op, True)
                
class NameMixin:
    @property
    def name(self):
        return self._name


    @name.setter
    def name(self, new):
        self._name = new

       
class Host(NameMixin):
    def __init__(self, name, fqdn):
        self._name = name
        self._fqdn = fqdn

    @property
    def fqdn(self):
        return self._fqdn

    @fqdn.setter
    def fqdn(self, new):
        self._fqdn = new

    def __str__(self):
        return self.fqdn
        
        
class Module(NameMixin):
    num_read_bytes = 1024
    
    def __init__(self, rules, host, name):
        self._rules = rules
        self._host = host
        self._name = name

    def load_from_file(self, file):
        interface = {}
        template = {}
        parse.parse_file(str(file), interface, template)

    def load_from_str(self, contents):
        while True:
            match = re.match(r'(?am)^\s*(#.*)\r?\n', contents)
            if match:
                (comment,) = match.groups()
                print("comment = %r"%comment)
                contents = contents[match.end():]
                continue
            
            match = re.match(r'(?am)^\s*(\w+)\s*', contents)
            assert match, contents[0:12] + '...'
            (word,) = match.groups()
            if contents[0] == '(':
                if word == "changequote":
                    assert False, "changequote unsupported"
                if word == "policy_module":
                    pass
            contents = contents[match.end():]
#            re.match(r'^\(\w
            print(contents[0])
            exit(1)


class ClassRules(NameMixin):
    def __init__(self, host, source, target, class_):
        self._name = class_
        self._rules = {}
        self._source = source
        self._target = target
        self._host = host
    def has_op(self, op, *args):
        if args:
            self._rules[op] = args[0]
        return op in self._rules
    

class TargetRules(NameMixin):
    def __init__(self, host, source, target):
        self._name = target
        self._rules = {}
        self._source = source
        self._host = host

    def class_(self, class_):
        if class_ not in self._rules:
            self._rules[class_] = ClassRules(self._host, self._source, self._name, class_)
        return self._rules[class_]
        
            
class SourceRules(NameMixin):
    def __init__(self, host, name):
        self._name = name
        self._rules = {}
        self._host = host
        self._iface_calls = {}

    def target(self, target):
        if target not in self._rules:
            self._rules[target] = TargetRules(self._host, self.name, target)
        return self._rules[target]

    def add_iface_call(self, line):
        match = re.match('^(\S+)\(([^,\)]+)(.*)\)$', line)
        assert match
        (iface, arg1, rest) = match.groups()
        if iface not in self._iface_calls:
            self._iface_calls[iface] = {}
        if rest not in self._iface_calls[iface]:
            self._iface_calls[iface][rest] = True

class HostRules(NameMixin):
    def __init__(self, name):
        self._name = name
        self._rules = {}

    def source(self, source):
        if source not in self._rules:
            self._rules[source] = SourceRules(self._name, source)
        return self._rules[source]
    

class Rules(NameMixin):
    def __init__(self, name):
        self._name = name
        self._hosts = []
        self._rules = {}

    def add_host(self, host):
        self._hosts.append(host)
        self._rules[host] = HostRules(host)

    def host(self, host):
        if host not in self._rules:
            self.add_host(host)
        return self._rules[host]
        

logger = logging.getLogger(__name__)

hostmap = dict(netra='netra.heptet.us')

ftypemap = {}
for ftype in ftypes:
    if hasattr(auparse, ftype):
        ftypemap[getattr(auparse, ftype)] = ftype
    

cmd = Path(sys.argv[0])
app_root = str(cmd.parent.absolute())

host = socket.gethostname()

parser = argparse.ArgumentParser(description="Manage SELinux modules")
parser.add_argument('--scontext', action='store', dest='scontext', help='Limit scontext to comma separated list')
# Audit2Allow argument
parser.add_argument("-r", "--requires", action="store_true", dest="requires", default=False,
                          help="generate require statements for rules")
parser.add_argument("-D", "--dontaudit", action="store_true",
                          dest="dontaudit", default=False,
                          help="generate policy with dontaudit rules")
parser.add_argument("-v", "--verbose", action="store_true", dest="verbose",
                  default=False, help="explain generated output")
parser.add_argument("-e", "--explain", action="store_true", dest="explain_long",
                  default=False, help="fully explain generated output")
parser.add_argument("--interface-info", dest="interface_info", help="file name of interface information")
parser.add_argument("--perm-map", dest="perm_map", help="file name of perm map")
parser.add_argument("-R", "--reference", action="store_true", dest="refpolicy",
                    default=True, help="generate refpolicy style output")
parser.add_argument("-N", "--noreference", action="store_false", dest="refpolicy", default=False, help="do not generate refpolicy style output")
parser.add_argument('--hostname', help="Specify hostname (default is %s)" % host,
                    default=host, action='store')
parser.add_argument('--input-directory', help="Specify input source directory for SElinux modules", default="generated", action="store")
parser.add_argument('--input-file', help="Specify audit log input for subprocess.",
                    action="store")
parser.add_argument('--search', '-s', help="Search the auditlog",
                    action="store")
args = parser.parse_args()

rules = Rules("rules")

# config file?
git_root = "git"
repo = {}
for elem in Path(git_root).iterdir():
    if elem.is_dir():
        host = elem.name
        repo[host] = Repo(str(elem.resolve()))
        rules.add_host(host)
        for file in elem.iterdir():
            if not file.name.endswith('.te'):
                continue
            module = Module(rules.host(host), host, file.name[0:len(file.name) - 2])
            module.load_from_file(file)


main_temp = TemporaryDirectory(dir="tempdirs")
print("main_temp = %s" % main_temp.name)
tempdir = {}
for host, host_repo in repo.items():
    x = host.split('.')
    x.reverse()
    mod_prefix = '_'.join(x)

    tempdir[host] = main_temp.name + "/" + host
    os.mkdir(tempdir[host])
    
    print("tempdir for %s is %s" % (host, tempdir[host]))


# I'm a bit unsure its wise to parse it but it sounded fun
def mycb(aup, cb_event_type, user_data):
    try:
        r = _mycb(aup, cb_event_type, user_data)
    except:
        print("%s" % sys.exc_info()[1])
        import traceback
        traceback.print_tb(sys.exc_info()[2])


def _mycb(aup, cb_event_type, user_data):
    if cb_event_type == auparse.AUPARSE_CB_EVENT_READY:
        if aup.first_record() < 0:
            return

        lines = []
        while True:
            event = aup.get_timestamp()
            if not user_data['cur_event'] or user_data['cur_event']['serial'] != event.serial:
                user_data['cur_event'] = dict(sec=event.sec, host=event.host, milli=event.milli, serial=event.serial, scontext=None)
                lines.append("----")
                dt = datetime.fromtimestamp(event.sec)
                lines.append("time->%s" % dt)
        
            mytype = aup.get_type_name()
            #print("type=%s" %mytype)
            message = mytype
            spec = "%d.%03d:%d" % (event.sec, event.milli, event.serial)
            message = "node=%s type=%s msg=audit(%s):" % (event.host, mytype, spec)
            vars = ""
            while True:
                f = aup.get_field_name()
                if not f in ("node", "type"):
                    t = aup.get_field_type()
                    v = aup.get_field_str()
                    procvar = False
                    if mytype == "AVC":
                        if f == "seresult":
                            message = message + " avc:  " + v
                            procvar = True
                        elif f == "seperms":
                            message = message + "  { " + v + " } for "
                            procvar = True
                        elif f == "scontext":
                            user_data['cur_event']['scontext'] = v

                    if not procvar:
                        vars = vars + " " + f + "=" + v
                
                if not aup.next_field(): break

            message = message + vars
            lines.append(message)
            if not aup.next_record(): break

        if event.host in hostmap:
            mapped_host = hostmap[event.host]
        else:
            mapped_host = event.host
        if mapped_host not in user_data['log']:
            user_data['log'][mapped_host] = []

        user_data['log'][mapped_host].extend(lines)

try:
    lines = None
    ausearch_out = None
    audit_lines = []

    if args.search:
        ausearch_proc = subprocess.Popen(['/sbin/ausearch', *(args.search.split(' '))], stdout=subprocess.PIPE)
        if ausearch_proc.returncode:
            print("ausearch subprocess failed");
            exit(1)

    assert ausearch_proc.stdout

    cmd = ['audit2allow']
    if args.refpolicy:
        cmd.append('-R')
    cmd.extend(['--interface-info', repo[host].working_tree_dir + '/interface_info',
                '--perm-map', repo[host].working_tree_dir + '/perm_map'])
    
    ausearch_output = b""
    all_allow_out = b""

    aup = auparse.AuParser(auparse.AUSOURCE_FEED)
    user_data = dict(cur_event=None, log={})
    aup.add_callback(mycb, user_data)
    
    while ausearch_proc.returncode is None:
        (stdout, stderr) = ausearch_proc.communicate()
        ausearch_output = ausearch_output + stdout

        #        (allow_out, allow_err) = audit2allowproc.communicate(stdout)
        #        all_allow_out = all_allow_out + allow_out
        
        result = aup.feed(stdout)

    aup.flush_feed()
    aup = None

    env = Environment(
        loader=FileSystemLoader(app_root),
        trim_blocks=True,
        lstrip_blocks=True,
        autoescape=False,
        )

    print(user_data['log'].keys(), sep="\t")
    for host in user_data['log']:
        x = host.split('.')
        x.reverse()
        mod_prefix = '_'.join(x)

        print("processing %s" % host)
        audit2allowproc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
        (allow_out, allow_err) = audit2allowproc.communicate(bytes('\n'.join(user_data['log'][host]) + '\n', encoding='utf-8'))
        
        print(allow_out)
    
        allow = allow_out.decode('utf-8')
        lines = allow.split('\n')

        source = None
        for line in lines:
            try:
                process_line(rules.host(host), line)
            except Exception  as ex:
                raise ex

        for source, sourcerules in rules.host(host)._rules.items():
            name = source[0:-2]
            module_name = '%s_%s' % (mod_prefix, name)
            t = env.get_template('module.jinja2')
            classes = {}
            rulesary = []
            types = { source: True }
            for target in sorted(sourcerules._rules.keys()):
                targetrules = sourcerules._rules[target]
                if not (target in types or target in ('self')):
                    types[target] = True
                
                for class_ in sorted(targetrules._rules.keys()):
                    ops = targetrules._rules[class_]._rules.keys()
                    rulesary.append('allow %s %s:%s { %s };' % (source, target, class_, ' '.join(sorted(ops))))
                    if not class_ in classes:
                        classes[class_] = {}
                    for op in ops:
                        classes[class_][op] = True

            for iface in sorted(sourcerules._iface_calls.keys()):
                calls = sourcerules._iface_calls[iface]
                for rest in sorted(calls.keys()):
                    rulesary.append("%s(%s%s)" % (iface, source, rest))
                
            fname = tempdir[host] + '/%s.te' % module_name;
            print("writing %s" % fname)
            classes2 = {}
            for k, v in classes.items():
                classes2[k] = list(sorted(v.keys()))

            with open(fname, 'w') as f:
                print(t.render(module_name=module_name,
                               sclasses=sorted(classes2.keys()),
                       classes=classes2,
                       rules=rulesary,
                               types=sorted(types.keys())), file=f)
    
#            mod_fname = tempdir[host] + '/%s.mod' % module_name
#            r = subprocess.run(['checkmodule', '-o', mod_fname, '-m', fname], stdout=subprocess.PIPE)
#            if r.returncode:
#    #            print(r.stderr.decode('utf-8'), file=sys.stderr)
#                print(fname)
#                exit(1)
#    
#            pp_out = tempdir[host] + '/%s.pp' % module_name
#            r = subprocess.run(['semodule_package', '-o', pp_out, '-m', mod_fname], stdout=subprocess.PIPE)
#            if r.returncode:
#    #            print(r.stderr.decode('utf-8'), file=sys.stderr)
#                exit(1)
#    
    print(tempdir)
except Exception as ex:
    raise ex
finally:
    output_dir = "output"
    shutil.rmtree(output_dir)
    os.mkdir(output_dir)
    for host, dir in tempdir.items():
        shutil.copytree(dir, "%s/%s" % (output_dir, host))
    
#json.dump(rules, fp=sys.stdout, indent=4)
os.chdir(app_root)
