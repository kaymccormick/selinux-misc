#!/usr/bin/python3


from selinux import string_to_security_class, string_to_av_perm, security_av_string, security_class_to_string
import sexpdata
import json
import sys
import re
from graphviz import Digraph
from semanage import semanage_handle_create, semanage_connect, \
    semanage_module_list, semanage_module_info_get_name, \
    semanage_module_key_create, semanage_module_get_module_info, \
    semanage_module_info_get_priority, semanage_module_key_set_priority, \
    semanage_module_extract, semanage_module_list_nth, semanage_module_key_set_name

refpolicy_dir = '/home/user/j/jade/refpolicy/'
obj_perm_sets_spt = '/home/user/j/jade/obj_perm_sets.spt'
output_dir = "/home/user/j/jade/public_html/graphs"
perm_sets_json = 'perm_sets.json'

class Macro:
    def __init__(self, name):
        self._name = name

    @property
    def name(self):
        return self._name

    @name.setter
    def name(self, new):
        self._name = new

class PermSet(Macro):
    pass

classes1 = {}
classes2 = {}
with open("classes.txt", "r") as f:
    for a in f:
        a = a.rstrip()
        r = string_to_security_class(a)
        classes1[a] = r
        classes2[r] = a


macro_perms = {}
with open(perm_sets_json, 'r') as f:
    perm_sets = json.load(f)
    def _():
        pass
    perm_sets2 = {}
    refs = {}
    for macro_name, ary in perm_sets.items():
        m_perms = []
        m_refs = []
        for perm in ary:
            if perm in perm_sets:
                m_refs.append(perm)
                if perm not in refs:
                    refs[perm] = []
                refs[perm].append(macro_name)
            else:
                m_perms.append(perm)
        perm_sets2[macro_name] = (m_perms, m_refs)

    def _resolve(mp, ps, refname):
        if refname in mp:
            return mp[refname]
        (p, r) = ps[refname]
        perms = []
        for ref in r:
            refperms = _resolve(mp, ps, ref)
            perms.extend(refperms)
        perms.extend(p)
        mp[refname] = perms
        return perms
            
    for macro_name in perm_sets.keys():
        if macro_name not in refs:
            m_perms = []
            (p,r) = perm_sets2[macro_name]
            for ref in r:
                refperms = _resolve(macro_perms, perm_sets2, ref)
                m_perms.extend(refperms)
            m_perms.extend(p)
            mp = {}
            for x in m_perms:
                mp[x] = True
            macro_perms[macro_name] = list(mp.keys())

def slurp_arg(contents):
    if(contents[0] == '`'):
        match = re.match(r'`([^`\']+)\'', contents)
        if match:
            argument = match.group(1)
            contents = contents[match.end():]
            return (contents, argument)
    return (contents,None)
            

def parse_obj_perm_sets(filename):
    perm_sets = {}
    with open(filename, 'r') as f:
        contents = ''.join(f.readlines())
        while contents:
            match = re.match(r'(?am)^\s*(#.*)\r?\n', contents)
            if match:
                (comment,) = match.groups()
                contents = contents[match.end():]
                continue
            
            match = re.match(r'(?am)^\s*(\w+)\s*', contents)
            if not match:
                lines = contents.split('\n')
                print("beep: ", lines[0])
                assert 0
                
            word = match.group(1)
            contents = contents[match.end():]
            if contents[0] == '(':
                if word == "changequote":
                    assert False, "changequote unsupported"
                if word == "policy_module":
                    pass
                if word == "define":
                    contents = contents[1:].lstrip()
                    (contents, arg) = slurp_arg(contents)
                    match = re.match(r'(?am)^,\s*', contents)
                    if not match:
                        print("derp: ", repr(contents))
                        assert 0
                    contents = contents[match.end():]
                    (contents, arg2) = slurp_arg(contents)
                    match2 = re.match('\s*{\s*(.*)\s*}\s*', arg2)
                    if match2:
                        permset = match2.group(1).rstrip()
                        perms = permset.split(' ')
                        my_perms = {}
                        for perm in perms:
                            my_perms[perm] = True

                        perm_sets[arg] = list(my_perms.keys())
                            
            contents = contents[match.end():]
    return perm_sets


#perm_sets = parse_obj_perm_sets(obj_perm_sets_spt)
#json.dump(perm_sets, fp=sys.stdout, indent=4)

#by_perms = {}
#for k, v in perm_sets.items():
#    # sorting doesn't make sense!
#    by_perms[' '.join(sorted(v))] = k
#

sh = semanage_handle_create()
if semanage_connect(sh):
   exit(1)
   
(a, modinfos, b) = semanage_module_list(sh)
i = 0
while i < b:
    module = semanage_module_list_nth(modinfos, i)
    (c, name) = semanage_module_info_get_name(sh, module)
    i = i + 1

    if not name.startswith('us_heptet'):
        continue
    print(name)

    format = 'svg'
    
    dot = Digraph(comment="Graph for module %s" % name, format=format)
#    dot.node('module %s' % module, 'Module %s' % name)
    
    (result, modkey) = semanage_module_key_create(sh)
    semanage_module_key_set_name(sh, modkey, name)
    
    (result, info) = semanage_module_get_module_info(sh, modkey)
    (result, priority) = semanage_module_info_get_priority(sh, info)
    semanage_module_key_set_priority(sh, modkey, priority)

    (result,module_content,*x) = semanage_module_extract(sh, modkey, True)
    xo = sexpdata.parse(module_content)
    for entry in xo:
        if entry[0].value() == "type":
            pass
        elif entry[0].value() == "typeattributeset":
            if entry[1].value() == "cil_gen_require":
                pass
#                dot.attr(color='blue')
#                dot.node('type %s' % entry[2].value(), 'type %s' % entry[2].value())
#                dot.edge('module %s' % name, 'type %s' % entry[2].value())
        elif entry[0].value() == "allow":
            (class_symbol, perms) = entry[3]

            class_name = class_symbol.value()
            security_class = string_to_security_class(class_name)
            
            #perm_str = '{'
            perm_str = ''
            permvals = []
            avs = 0
            perms2 = []
            for p in perms:
                perm = p.value()
                if perm in macro_perms:
                    perms2.extend(macro_perms[perm])
                else:
                    perms2.append(perm)

            for perm in perms2:
                perm_av = string_to_av_perm(security_class, perm)
                avs = avs | perm_av
                print("%16s %08x" % (perm, perm_av))
                permvals.append(perm)

            (result, av_string) = security_av_string(security_class, avs)
            if not result:
                print("AV string is %s" % av_string)
            
            permvals = sorted(permvals)
            perm_str = ' '.join(permvals)
            #perm_str += ' }'
            perm_str = perm_str.lstrip()
                
            dot.edge('type %s' % entry[1].value(), 'type %s' % entry[2].value(),
                     class_symbol.value() + ' ' + perm_str)

    
    with open(output_dir + '/' + name + '.gv', 'w') as f:
        f.write(dot.source)
        
    dot.render(output_dir + '/' + name, view=False)

        
