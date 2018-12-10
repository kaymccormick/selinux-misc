import setools
from setools.policyrep import NoCommon
import sys
import json
from selinux import security_class_to_string, string_to_security_class, string_to_av_perm


def main():
    p = setools.SELinuxPolicy()
    for class_ in p.classes():
        print(repr(class_))
    exit(0)
    q = setools.ObjClassQuery(p)
    results  = q.results()
    datas = {}
    if True:
        for item in results:
            inherits = None
            try:
                inherits = item.common
            except NoCommon:
                pass
            
            name = str(item)
            if name == 'file':
                print(repr(item.__dict__))
                print(repr(item.statement()))
                print(repr(inherits.statement()))
            p = []
            s_class = string_to_security_class(name)
            for perm in item.perms:
                av_t = string_to_av_perm(s_class, str(perm))
                
                p.append([str(perm), "0x%08X" % av_t])
            

            inherits_name = str(inherits)
            data = dict(inherits=str(inherits),
                        perms=p,
                        name=name)
            data['security_class'] = s_class
            datas[data['name']] = data

                
        print("")
    
