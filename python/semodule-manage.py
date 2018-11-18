#!/usr/bin/env python3.7
## File: semodule-manage.py
## Author: Kay McCormick
##
## Error handling was kinda gutted, it should be replaced.
##
## following is pulled from enum, could probably use a regexp.
ftypes=['AUPARSE_TYPE_UNCLASSIFIED','AUPARSE_TYPE_UID','AUPARSE_TYPE_GID','AUPARSE_TYPE_SYSCALL','AUPARSE_TYPE_ARCH','AUPARSE_TYPE_EXIT','AUPARSE_TYPE_ESCAPED','AUPARSE_TYPE_PERM','AUPARSE_TYPE_MODE','AUPARSE_TYPE_SOCKADDR','AUPARSE_TYPE_FLAGS','AUPARSE_TYPE_PROMISC','AUPARSE_TYPE_CAPABILITY','AUPARSE_TYPE_SUCCESS','AUPARSE_TYPE_A0','AUPARSE_TYPE_A1','AUPARSE_TYPE_A2','AUPARSE_TYPE_A3','AUPARSE_TYPE_SIGNAL','AUPARSE_TYPE_LIST','AUPARSE_TYPE_TTY_DATA','AUPARSE_TYPE_SESSION','AUPARSE_TYPE_CAP_BITMAP','AUPARSE_TYPE_NFPROTO','AUPARSE_TYPE_ICMPTYPE','AUPARSE_TYPE_PROTOCOL','AUPARSE_TYPE_ADDR','AUPARSE_TYPE_PERSONALITY','AUPARSE_TYPE_SECCOMP','AUPARSE_TYPE_OFLAG','AUPARSE_TYPE_MMAP','AUPARSE_TYPE_MODE_SHORT','AUPARSE_TYPE_MAC_LABEL','AUPARSE_TYPE_PROCTITLE','AUPARSE_TYPE_HOOK','AUPARSE_TYPE_NETACTION','AUPARSE_TYPE_MACPROTO','AUPARSE_TYPE_IOCTL_REQ','AUPARSE_TYPE_ESCAPED_KEY','AUPARSE_TYPE_ESCAPED_FILE','AUPARSE_TYPE_FANOTIFY']

import semanage
import audit
import auparse
import sepolgen.policygen as policygen
import sepolgen.defaults as defaults
import sepolgen.interfaces as interfaces
import sepolgen.objectmodel as objectmodel
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

class AuditParser:
    """Parser for audit messages.

    This class parses audit messages and stores them according to their message
    type. This is not a general purpose audit message parser - it only extracts
    selinux related messages.

    Each audit messages are stored in one of four lists:
       avc_msgs - avc denial or granted messages. Messages are stored in
          AVCMessage objects.
       comput_sid_messages - invalid sid messages. Messages are stored in
          ComputSidMessage objects.
       invalid_msgs - selinux related messages that are not valid. Messages
          are stored in InvalidMessageObjects.
       policy_load_messages - policy load messages. Messages are stored in
          PolicyLoadMessage objects.

    These lists will be reset when a policy load message is seen if
    AuditParser.last_load_only is set to true. It is assumed that messages
    are fed to the parser in chronological order - time stamps are not
    parsed.
    """
    def __init__(self, last_load_only=False):
        self.__initialize()
        self.last_load_only = last_load_only

    def __initialize(self):
        self.avc_msgs = []
        self.compute_sid_msgs = []
        self.invalid_msgs = []
        self.policy_load_msgs = []
        self.path_msgs = []
        self.by_header = { }
        self.check_input_file = False
                
    # Low-level parsing function - tries to determine if this audit
    # message is an SELinux related message and then parses it into
    # the appropriate AuditMessage subclass. This function deliberately
    # does not impose policy (e.g., on policy load message) or store
    # messages to make as simple and reusable as possible.
    #
    # Return values:
    #   None - no recognized audit message found in this line
    #
    #   InvalidMessage - a recognized but invalid message was found.
    #
    #   AuditMessage (or subclass) - object representing a parsed
    #      and valid audit message.
    def __parse_line(self, line):
        # strip("\x1c\x1d\x1e\x85") is only needed for python2
        # since str.split() in python3 already does this
        rec = [x.strip("\x1c\x1d\x1e\x85") for x in line.split()]
        for i in rec:
            found = False
            if i == "avc:" or i == "message=avc:" or i == "msg='avc:":
                msg = AVCMessage(line)
                found = True
            elif i == "security_compute_sid:":
                msg = ComputeSidMessage(line)
                found = True
            elif i == "type=MAC_POLICY_LOAD" or i == "type=1403":
                msg = PolicyLoadMessage(line)
                found = True
            elif i == "type=AVC_PATH":
                msg = PathMessage(line)
                found = True
            elif i == "type=DAEMON_START":
                msg = DaemonStartMessage(list)
                found = True
                
            if found:
                self.check_input_file = True
                try:
                    msg.from_split_string(rec)
                except ValueError:
                    msg = InvalidMessage(line)
                return msg
        return None

    # Higher-level parse function - take a line, parse it into an
    # AuditMessage object, and store it in the appropriate list.
    # This function will optionally reset all of the lists when
    # it sees a load policy message depending on the value of
    # self.last_load_only.
    def __parse(self, line):
        msg = self.__parse_line(line)
        if msg is None:
            return

        # Append to the correct list
        if isinstance(msg, PolicyLoadMessage):
            if self.last_load_only:
                self.__initialize()
        elif isinstance(msg, DaemonStartMessage):
            # We initialize every time the auditd is started. This
            # is less than ideal, but unfortunately it is the only
            # way to catch reboots since the initial policy load
            # by init is not stored in the audit log.
            if msg.auditd and self.last_load_only:
                self.__initialize()
            self.policy_load_msgs.append(msg)
        elif isinstance(msg, AVCMessage):
            self.avc_msgs.append(msg)
        elif isinstance(msg, ComputeSidMessage):
            self.compute_sid_msgs.append(msg)
        elif isinstance(msg, InvalidMessage):
            self.invalid_msgs.append(msg)
        elif isinstance(msg, PathMessage):
            self.path_msgs.append(msg)

        # Group by audit header
        if msg.header != "":
            if msg.header in self.by_header:
                self.by_header[msg.header].append(msg)
            else:
                self.by_header[msg.header] = [msg]
            

    # Post processing will add additional information from AVC messages
    # from related messages - only works on messages generated by
    # the audit system.
    def __post_process(self):
        for value in self.by_header.values():
            avc = []
            path = None
            for msg in value:
                if isinstance(msg, PathMessage):
                    path = msg
                elif isinstance(msg, AVCMessage):
                    avc.append(msg)
            if len(avc) > 0 and path:
                for a in avc:
                    a.path = path.path

    def parse_file(self, input):
        """Parse the contents of a file object. This method can be called
        multiple times (along with parse_string)."""
        line = input.readline()
        while line:
            self.__parse(line)
            line = input.readline()
        if not self.check_input_file:
            sys.stderr.write("Nothing to do\n")
            sys.exit(0)
        self.__post_process()

    def parse_string(self, input):
        """Parse a string containing audit messages - messages should
        be separated by new lines. This method can be called multiple
        times (along with parse_file)."""
        lines = input.split('\n')
        for l in lines:
            self.__parse(l)
        self.__post_process()

    def to_role(self, role_filter=None):
        """Return RoleAllowSet statements matching the specified filter

        Filter out types that match the filer, or all roles

        Params:
           role_filter - [optional] Filter object used to filter the
              output.
        Returns:
           Access vector set representing the denied access in the
           audit logs parsed by this object.
        """
        role_types = access.RoleTypeSet()
        for cs in self.compute_sid_msgs:
            if not role_filter or role_filter.filter(cs):
                role_types.add(cs.invalid_context.role, cs.invalid_context.type)
        
        return role_types

    def to_access(self, avc_filter=None, only_denials=True):
        """Convert the audit logs access into a an access vector set.

        Convert the audit logs into an access vector set, optionally
        filtering the restults with the passed in filter object.

        Filter objects are object instances with a .filter method
        that takes and access vector and returns True if the message
        should be included in the final output and False otherwise.

        Params:
           avc_filter - [optional] Filter object used to filter the
              output.
        Returns:
           Access vector set representing the denied access in the
           audit logs parsed by this object.
        """
        av_set = access.AccessVectorSet()
        for avc in self.avc_msgs:
            if avc.denial != True and only_denials:
                continue
            if avc_filter:
                if avc_filter.filter(avc):
                    av_set.add(avc.scontext.type, avc.tcontext.type, avc.tclass,
                               avc.accesses, avc, avc_type=avc.type, data=avc.data)
            else:
                av_set.add(avc.scontext.type, avc.tcontext.type, avc.tclass,
                           avc.accesses, avc, avc_type=avc.type, data=avc.data)
        return av_set

class Audit2Allow:
    def __init__(self, options):
        self.__options = options

    def output(self):
        return self._output()
    
    def _output(self):

        g = policygen.PolicyGenerator()

        g.set_gen_dontaudit(self.__options.dontaudit)

        if self.__options.module:
            g.set_module_name(self.__options.module)

        # Interface generation
        if self.__options.refpolicy:
            ifs, perm_maps = self.__load_interface_info()
            g.set_gen_refpol(ifs, perm_maps)

        # Explanation
        if self.__options.verbose:
            g.set_gen_explain(policygen.SHORT_EXPLANATION)
        if self.__options.explain_long:
            g.set_gen_explain(policygen.LONG_EXPLANATION)

        # Requires
        if self.__options.requires:
            g.set_gen_requires(True)

        # Generate the policy
        g.add_access(self.__avs)
        g.add_role_types(self.__role_types)

        # Output
        writer = output.ModuleWriter()

        # Module package
        if self.__options.module_package:
            self.__output_modulepackage(writer, g)
        else:
            # File or stdout
            if self.__options.module:
                g.set_module_name(self.__options.module)

            if self.__options.output:
                fd = open(self.__options.output, "a")
            else:
                fd = sys.stdout
            writer.write(g.get_module(), fd)

    def __load_interface_info(self):
        # Load interface info file
        if self.__options.interface_info:
            fn = self.__options.interface_info
        else:
            fn = defaults.interface_info()
        try:
            fd = open(fn)
        except:
            sys.stderr.write("could not open interface info [%s]\n" % fn)
            sys.exit(1)

        ifs = interfaces.InterfaceSet()
        ifs.from_file(fd)
        fd.close()

        # Also load perm maps
        if self.__options.perm_map:
            fn = self.__options.perm_map
        else:
            fn = defaults.perm_map()
        try:
            fd = open(fn)
        except:
            sys.stderr.write("could not open perm map [%s]\n" % fn)
            sys.exit(1)

        perm_maps = objectmodel.PermMappings()
        perm_maps.from_file(fd)

        return (ifs, perm_maps)


logger = logging.getLogger(__name__)

ftypemap = {}
for ftype in ftypes:
    if hasattr(auparse, ftype):
        ftypemap[getattr(auparse, ftype)] = ftype
    

cmd = Path(sys.argv[0])
app_root = str(cmd.parent.absolute())

host = socket.gethostname()

parser = argparse.ArgumentParser(description="Manage SELinux modules")
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

host = args.hostname

x = host.split('.')
x.reverse()
mod_prefix = '_'.join(x)


rules = {}

generated = Path(args.input_directory)
comment = ''
# fix glob
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

# I'm a bit unsure its wise to parse it but it sounded fun
def mycb(aup, cb_event_type, user_data):
    try:
        r = _mycb(aup, cb_event_type, user_data)
    except:
        print("%s", sys.exc_info()[1])
        sys.exit(1)

def _mycb(aup, cb_event_type, user_data):
    if cb_event_type == auparse.AUPARSE_CB_EVENT_READY:
        if aup.first_record() < 0:
            return

        #print("num_records = %d" % aup.get_num_records())

        first_event = True
        lines = []
        while True:
            event = aup.get_timestamp()
            if not user_data['cur_event'] or user_data['cur_event']['serial'] != event.serial:
                user_data['cur_event'] = dict(sec=event.sec, host=event.host, milli=event.milli, serial=event.serial)
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

                    if not procvar:
                        vars = vars + " " + f + "=" + v
                
                if not aup.next_field(): break

            message = message + vars
            lines.append(message)
            if not aup.next_record(): break

        user_data['proc'].stdin.write(bytes('\n'.join(lines) + '\n', encoding='utf-8'))


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

    assert ausearch_proc.stdout

    audit2allowproc = subprocess.Popen(['audit2allow', '-v'], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
#    audit2allowproc = subprocess.Popen(['/bin/bash', '/home/user/j/jade/src/selinux-misc/python/me'], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    ausearch_output = b""
    all_allow_out = b""

    aup = auparse.AuParser(auparse.AUSOURCE_FEED)
    user_data = dict(proc=audit2allowproc, cur_event=None)
    aup.add_callback(mycb, user_data)
    
    while ausearch_proc.returncode is None:
        (stdout, stderr) = ausearch_proc.communicate()
        ausearch_output = ausearch_output + stdout

        #        (allow_out, allow_err) = audit2allowproc.communicate(stdout)
        #        all_allow_out = all_allow_out + allow_out
        
        result = aup.feed(stdout)

    aup.flush_feed()

    (allow_out, allow_err) = audit2allowproc.communicate()
    print(allow_out)
    
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
        def setup_policygen(name):
            args.module = name
            a = Audit2Allow(args)
            
            a.output()
            return a
    
        name = source[0:-2]
        module_name = '%s_%s' % (mod_prefix, name)
        a = setup_policygen(module_name)

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

