import re
import logging

logger = logging.getLogger(__name__)

_my_class = r'-!&~{}:/\w_"\*\$\.;'
COMMENT_REGEXP = r'#.*'
COMMENT_PATTERN = re.compile(COMMENT_REGEXP)
QUOTED_REGEXP = r'(?am)([' + _my_class + r',\(\)\s]*)'
QUOTED_PATTERN = re.compile(QUOTED_REGEXP)
UNQUOTED_REGEXP = r'(?am)([' + _my_class + r']*)'
UNQUOTED_PATTERN = re.compile(UNQUOTED_REGEXP)

UNQUOTED_ARG_TERM_EATCOMMA = r'(?am)(,\s*|\)\s*)'
QUOTED_ARG_TERM_EATCOMMA = r'(?am)\'(,\s*|\)\s*)'
UNQUOTED_ARG_TERM = '(?am)\s*'
QUOTED_ARG_TERM = '(?am)\'\s*'
UNQUOTED_ARG_TERM_EATCOMMA_PATTERN = re.compile(UNQUOTED_ARG_TERM_EATCOMMA)
QUOTED_ARG_TERM_EATCOMMA_PATTERN = re.compile(QUOTED_ARG_TERM_EATCOMMA)
UNQUOTED_ARG_TERM_PATTERN = re.compile(UNQUOTED_ARG_TERM)
QUOTED_ARG_TERM_PATTERN = re.compile(QUOTED_ARG_TERM)

COMMENT2_REGEXP = r'(?am)^\s*(#.*)'
COMMENT2_PATTERN = re.compile(COMMENT2_REGEXP)

INVOKEMACRO_REGEXP = r'(?am)^\s*([-!&~{}:/\w_"\*\$,\.;]+)\s*'
INVOKEMACRO_PATTERN = re.compile(INVOKEMACRO_REGEXP)


class ParseError(Exception):
    def __init__(self, file, pos):
        self._file = file
        self._pos = pos

        
class NameMixin:
    @property
    def name(self):
        return self._name


    @name.setter
    def name(self, new):
        self._name = new

       
class Interface(NameMixin):
    def __init__(self, name, file, file_pos):
        self._name = name
        self._file = file
        self._file_pos = file_pos

    @property
    def file(name):
        return self._file

    @property
    def file_pos(self):
        return self._file_pos

    def __repr__(self):
        return "Interface(%r, %r, %r)" % (self._name, self._file, self._file_pos)
        

def slurp_arg(contents, eat_comma=True):
    logger.debug("1Contents = %s", contents[0:32])

    quoted = False
    if(contents[0] == '`'):
        contents = contents[1:]
        quoted = True

    logger.debug("2Contents = %s", contents[0:32])
        
    argument = ''
    while True:
        contents = contents.lstrip()
        match = COMMENT_PATTERN.match(contents)
        if match:
            contents = contents[match.end():]
            continue

        if quoted:
            match = QUOTED_PATTERN.match(contents)
        else:
            rgxp = UNQUOTED_PATTERN.match(contents)
            
        if match:
            argument += match.group(1)
            logger.debug("%r", match)
            contents = contents[match.end():]
            logger.debug("3Contents = %s", contents[0:32])
            termchar = '\''
            if not quoted:
                termchar = ''

            if eat_comma:
                if quoted:
                    pattern = QUOTED_ARG_TERM_EATCOMMA_PATTERN
                else:
                    pattern = UNQUOTED_ARG_TERM_EATCOMMA_PATTERN
            else:
                if quoted:
                    pattern = QUOTED_ARG_TERM_PATTERN
                else:
                    pattern = UNQUOTED_ARG_TERM_PATTERN
                    
            submatch = pattern.match(contents)

            if submatch:
                contents = contents[submatch.end():]
                isend = eat_comma and submatch.group(1).find(')') != -1
                logger.debug("submatch: %r", submatch)
                logger.debug("4Contents = %s", contents[0:32])
                return (contents, argument, isend)
                    
            if contents[0] == '`':
                (contents,result,isend) = slurp_arg(contents)
                logger.debug("5Contents = %s", contents[0:32])
                argument += result

    return (contents,None,True)
            

def parse_file(filename, interface, template, preserve_comments=True):
    pos = 0
    file_ary = []
    with open(filename, 'r') as f:
        comments = []
        contents = ''.join(f.readlines())
        while contents.strip():
            match = COMMENT2_PATTERN.match(contents)
            if match:
                (comment,) = match.groups()
                if preserve_comments:
                    file_ary.append(('comment', comment))
                comments.append(comment)
                contents = contents[match.end():]
                logger.debug("incrementing position (%d) by %d (to %d)", pos,
                             match.end(), pos + match.end())
                pos = pos + match.end()
                continue

            logger.debug("pos = %d", pos)
            cur_len = len(contents)
            contents = contents.lstrip()
            pos += cur_len - len(contents)
            logger.debug("pos = %d", pos)

            preinvoke_pos = pos
            match = INVOKEMACRO_PATTERN.match(contents)
            logger.debug("%r", match)
            if not match:
                logger.debug("ZContents = %s", contents[0:32])
                lines = contents.split('\n')
                logger.critical("beep: (%s:%d) %s",filename, pos,lines[0])
                raise ParseError()
                
            word = match.group(1)
            contents = contents[match.end():]
            logger.debug("incrementing position (%d) by %d (to %d)", pos,
                         match.end(), pos + match.end())
            pos = pos + match.end()
            
            cur_tuple = ()
            if len(contents) and contents[0] == '(':
                logging.debug(word)
                
                contents = contents[1:].lstrip()
                pos += 1
                
                isend = False
                cmd = word
                args = []
                old_len = len(contents)
                if cmd == "interface":
                    (contents, name, isend) = slurp_arg(contents)
                    ary = []
                    my_interface = Interface(name, file=filename, file_pos=preinvoke_pos)
                    interface[name] = my_interface
                    args.append(name)
                if cmd == "template":
                    (contents, name, isend) = slurp_arg(contents)
                    args.append(name)
                    ary = []
                    template[name] = (filename, pos, ary)

                while not isend:
                    (new_c, arg, isend) = slurp_arg(contents)
                    logger.debug("Slurped argument (len %d): %s" %( len(arg), arg))
                    args.append(arg)
                    
                    if arg is None:
                        print("new_c",new_c[0:32])
                        print("old_c",contents[0:32])
                        raise ParseError(file, pos)

                    contents = new_c

                logger.debug("incrementing position (%d) by %d (to %d)", pos,
                             old_len - len(contents), pos + (old_len - len(contents)))
                pos += old_len - len(contents)

                file_ary.append((cmd, args))
        
            
    return file_ary

if __name__ == '__main__':
    import sys
    import json

    logging.basicConfig(level=logging.WARNING)
    
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
        r = parse_file(filename, interface, template, preserve_comments=False)
        print(filename, file=sys.stdout)
        json.dump(r, fp=sys.stdout, indent=4)
    
    for iface in interface.keys():
        (file, pos, ary) = interface[iface]
        print("I:%24s %s:%4d" % (iface, file, pos))

    for iface in template.keys():
        (file, pos, ary) = template[iface]
        print("T:%24s %s:%4d" % (iface, file, pos))
