#!/usr/bin/python3


from selinux import string_to_security_class, string_to_av_perm, security_av_string
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
#            print(repr(contents))
            match = re.match(r'(?am)^\s*(#.*)\r?\n', contents)
            if match:
#                print("match1")
                (comment,) = match.groups()
#                print("comment = %r"%comment)
                contents = contents[match.end():]
                continue
            
            match = re.match(r'(?am)^\s*(\w+)\s*', contents)
            if not match:
                lines = contents.split('\n')
                print("beep: ", lines[0])
                assert 0
                
            word = match.group(1)
            print("word is ", word)
            contents = contents[match.end():]
            if contents[0] == '(':
                if word == "changequote":
                    assert False, "changequote unsupported"
                if word == "policy_module":
                    pass
                if word == "define":
                    print("in define")
                    contents = contents[1:].lstrip()
                    (contents, arg) = slurp_arg(contents)
                    match = re.match(r'(?am)^,\s*', contents)
                    if not match:
                        print("derp: ", repr(contents))
                        assert 0
                    contents = contents[match.end():]
                    print("arg is", arg)
                    (contents, arg2) = slurp_arg(contents)
                    match2 = re.match('\s*{\s*(.*)\s*}\s*', arg2)
                    if match2:
                        permset = match2.group(1).rstrip()
                        perms = permset.split(' ')
                        my_perms = {}
                        for perm in perms:
                            print(repr(perm))
                            if perm in perm_sets:
                                for perm2 in perm_sets[perm]:
                                    print("%s %s" % (perm, perm2))
                                    my_perms[perm2] = True

                            else:
                                my_perms[perm] = True

                        print("stashing for %s" %arg)
                        perm_sets[arg] = list(my_perms.keys())
                        print("for %r" %perm_sets[arg])
                        
                            
                            
            contents = contents[match.end():]
    return perm_sets


o            
perm_sets = parse_obj_perm_sets(obj_perm_sets_spt)
json.dump(perm_sets, fp=sys.stdout)
by_perms = {}
for k, v in perm_sets.items():
    by_perms[' '.join(sorted(v))] = k

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
    
    dot = Digraph(comment="Graph for module %s" % name, format='svg')
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
            for p in perms:
                perm = p.value()
                perm_av = string_to_av_perm(security_class, perm)
                avs = avs | perm_av
                print("%16s %08x" % (perm, perm_av))
                permvals.append(perm)

            print("SECUREITY ", security_av_string(security_class, avs))

            permvals = sorted(permvals)
            perm_str = ' '.join(permvals)
            #perm_str += ' }'
            perm_str = perm_str.lstrip()
            perm_macro = ''
            if perm_str in by_perms:
                perm_macro = by_perms[perm_str]
                perm_str = perm_macro
                print("YAY", perm_macro)
                
            dot.edge('type %s' % entry[1].value(), 'type %s' % entry[2].value(),
                     class_symbol.value() + ' ' + perm_str)

    
    with open(output_dir + '/' + name + '.gv', 'w') as f:
        f.write(dot.source)
        
    dot.render(output_dir + '/' + name, view=False)

        
