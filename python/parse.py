import sys
import re
import logging

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

def slurp_arg(contents, eat_comma=True):
    logger.info("1Contents = %s", contents[0:32])

    quoted = False
    if(contents[0] == '`'):
        contents = contents[1:]
        quoted = True

    logger.info("2Contents = %s", contents[0:32])
        
    argument = ''
    my_class = r'-!&~{}:/\w_"\*\$\.;'
    logger.info(my_class)
    while True:
        contents = contents.lstrip()
        match = re.match(r'#.*', contents)
        if match:
            contents = contents[match.end():]
            continue

        if quoted:
            rgxp = r'(?am)([' + my_class + r',\(\)\s]*)'
            logger.debug("regexp is %s", rgxp)
            match = re.match(rgxp, contents)

        else:
            rgxp = r'(?am)([' + my_class + r']*)'
            logger.debug("regexp is %s", rgxp)
            match = re.match(rgxp, contents)
            
        if match:
            logger.info("here mtch")
            argument += match.group(1)
            logger.info("%r", match)
            contents = contents[match.end():]
            logger.info("3Contents = %s", contents[0:32])
            termchar = '\''
            if not quoted:
                termchar = ''
                
            if eat_comma:
                submatch = re.match(r'(?am)' + termchar + '(,\s*|\)\s*)', contents)
            else:
                submatch = re.match(r'(?am)' + termchar + '\s*', contents)

            if submatch:
                contents = contents[submatch.end():]
                isend = eat_comma and submatch.group(1).find(')') != -1
                logger.info("submatch: %r", submatch)
                logger.info("4Contents = %s", contents[0:32])
                return (contents, argument, isend)
                    
            if contents[0] == '`':
                (contents,result,isend) = slurp_arg(contents)
                logger.info("5Contents = %s", contents[0:32])
                argument += result

    return (contents,None,True)
            

def parse_file(filename, interface, template):
    pos = 0
    with open(filename, 'r') as f:
        comments = []
        contents = ''.join(f.readlines())
        while contents.strip():
            match = re.match(r'(?am)^\s*(#.*)', contents)
            if match:
                (comment,) = match.groups()
#                print(comment)
                comments.append(comment)
                contents = contents[match.end():]
                pos = pos + match.end()
                continue

            logger.debug("pos = %d", pos)
            cur_len = len(contents)
            contents = contents.lstrip()
            pos += len(contents) - cur_len
            logger.debug("pos = %d", pos)
            
            match = re.match(r'(?am)^\s*([-!&~{}:/\w_"\*\$,\.;]+)\s*', contents)
            logger.debug("%r", match)
            if not match:
                logger.info("ZContents = %s", contents[0:32])
                lines = contents.split('\n')
                logger.critical("beep: (%s:%d) %s",filename, pos,lines[0])
                assert 0
                
            word = match.group(1)
            contents = contents[match.end():]
            pos = pos + match.end()
            cur_len = len(contents)
            if len(contents) and contents[0] == '(':
                logging.warning(word)
                contents = contents[1:].lstrip()
                pos += 1
                isend = False
                if word == "interface":
                    (contents, name, isend) = slurp_arg(contents)
                    ary = []
                    interface[name] = (filename, pos, ary)
                if word == "template":
                    (contents, name, isend) = slurp_arg(contents)
                    ary = []
                    template[name] = (filename, pos, ary)

                while not isend:
                    logger.debug("gonna slurp arg")
                    (new_c, arg, isend) = slurp_arg(contents)
                    logger.debug("dome slurping, got (%d) %s" %(len(arg), arg))
                    
                    if arg is None:
                        print("new_c",new_c[0:32])
                        print("old_c",contents[0:32])
                        assert 0
                    pos += len(contents) - len(new_c)
                    contents = new_c

            
    return True

if __name__ == '__main__':
    interface = {}
    template = {}

    if len(sys.argv) > 1:
        files = sys.argv[1:]
    else:
        files = []
        for filename in sys.stdin:
            files.append(filename.rstrip())

    for filename in files:
        logger.info(filename)
        r = parse_file(filename, interface, template)
    
    for iface in interface.keys():
        (file, pos, ary) = interface[iface]
        print("I:%24s %s:%4d" % (iface, file, pos))

    for iface in template.keys():
        (file, pos, ary) = template[iface]
        print("T:%24s %s:%4d" % (iface, file, pos))
