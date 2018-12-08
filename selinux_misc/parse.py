import re
import logging
from pathlib import Path

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
UNQUOTED_ARG_TERM = r'(?am)\s*'
QUOTED_ARG_TERM = r'(?am)\'\s*'
UNQUOTED_ARG_TERM_EATCOMMA_PATTERN = re.compile(UNQUOTED_ARG_TERM_EATCOMMA)
QUOTED_ARG_TERM_EATCOMMA_PATTERN = re.compile(QUOTED_ARG_TERM_EATCOMMA)
UNQUOTED_ARG_TERM_PATTERN = re.compile(UNQUOTED_ARG_TERM)
QUOTED_ARG_TERM_PATTERN = re.compile(QUOTED_ARG_TERM)

COMMENT2_REGEXP = r'(?am)^\s*(#.*)'
COMMENT2_PATTERN = re.compile(COMMENT2_REGEXP)

# this doesnt include the ( of the invocation and is thus misnamed
INVOKEMACRO_REGEXP = r'(?am)^\s*([-!&~{}:/\w_"\*\$,\.;]+)\s*'
INVOKEMACRO_PATTERN = re.compile(INVOKEMACRO_REGEXP)

#TAG_REGEXP = r'(?am)(<([^\s/][^\s>]+)(\s+[^>]*)?>)(.*)((</\2>)(.*))?$'
TAG_REGEXP = r'(?am)(<([^\s/][^\s>]+)(\s+[^>]*)?>)(.*)((</$2>)(.*))?$'

class NoParse(Exception):
    pass

class ParseError(Exception):
    def __init__(self, file, pos):
        self._file = file
        self._pos = pos


PARSEENTRY_COMMENT = 1
        

class ParseEntry:
    def __init__(self, pe_type):
        self._type = pe_type


class CommentParseEntry(ParseEntry):
    def __init__(self, comment):
        super().__init__(PARSEENTRY_COMMENT)
        self._comment = comment
    def __repr__(self):
        return "Comment(%r)" % self._comment
        


class ParseContext:
    def __init__(self, filename):
        self._filename = filename
        self._pos = 0
        self._interface = {}
        self._template = {}
        self._flags = 0
        self._line = None
        self._handle_comment = None

    def open(self):
        self._file = open(self._filename, 'r')
        return self._file

    def log_status(self, log_cb):
        log_cb("STATUS: Line is %r" % self._line)
        log_cb("STATUS: tell pos = %d" % self._file.tell())

    def match(self, pattern, consume=True):
        # probably shoudn't read within match ?
        while not self._line or self._line.isspace():
            self._line = self._file.readline()
            if not self._line:
                return None
        self.log_status(logger.debug)
        logger.debug("matching against %r", pattern)
        log_content(logger.debug, self._line)
        match_result = re.match(pattern, self._line)
        if not match_result:
            logger.debug("No match")
            return None

        logger.debug("Match is %r", match_result)
        if consume:
            if len(self._line) > match_result.end():
                try:
                    self._line = self._line[match_result.end():]
                except IndexError:
                    logger.critical("end is %d", match_result.end())
                    log_content(logger.critical, self._line)
            else:
                self._line = None
            
        return match_result
        
    @property
    def pos(self):
        return self._pos

    @pos.setter
    def pos(self, new):
        self._pos = new

    @property
    def interface(self):
        return self._interface

    @property
    def template(self):
        return self._template

    @property
    def handle_comment(self):
        return self._handle_comment

    @handle_comment.setter
    def handle_comment(self, new):
        self._handle_comment =  new

        
class NameMixin:
    @property
    def name(self):
        return self._name

    @name.setter
    def name(self, new):
        self._name = new


class ParseSource(NameMixin):
    pass


def FileParseSource(ParseSource):
    def __init__(self, filename):
        self._file_path = Path(filename)
        self._name = self._file_path.name
    
       
class Interface(ParseEntry):
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

def log_content(logcall, contents):
    logcall("log_content [len=%d]: %r" % (len(contents), contents[0:32]))


def slurp_arg(pcontext,eat_comma=True):
    pcontext.log_status(logger.debug)

    quoted = False
    if pcontext.match(r'`'):
        quoted = True

    logger.debug("slurp_arg (%r)", quoted)
        
    argument = ''
    while True:
        match = pcontext.match(COMMENT_PATTERN)
        if match:
            continue

        pattern = quoted and QUOTED_PATTERN or UNQUOTED_PATTERN
        match = pcontext.match(pattern)
        if match:
            argument += match.group(1)
            logger.debug("match = %r", match)
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
                    
            submatch = pcontext.match(pattern)

            if submatch:
                isend = eat_comma and submatch.group(1).find(')') != -1
                logger.debug("submatch: %r", submatch)
                return (True, argument, isend)

            if pcontext.match(r'`', consume=False):
                (r,result,isend) = slurp_arg(pcontext)
                argument += result

    return (True,None,True)


def parse_comment(pcontext):
    match = pcontext.match(COMMENT2_PATTERN)
    if not match:
        raise NoParse
    (comment,) = match.groups()
    if comment.find('<') != -1:
        logger.warning("looking for tag")
        tag_match = re.search(TAG_REGEXP, comment)
        if tag_match:
            logger.warning("match is %r (%r)", match, len(match.groups()))
            tag = tag_match.group(1)
            tag_name = tag_match.group(2)
            if tag_match.group(5):
                tag_content = tag_match.group(4)
                logger.critical("tg_content=%r", tag_content)
            if tag_name == 'summary':
                #pcontext.flags |= IN_SUMMARY
                pass

            comment_text = tag_match.group(4)
            logger.info("comment text is %r", comment_text)
            
    logger.debug("incrementing position (%d) by %d (to %d)", pcontext.pos,
                 match.end(), pcontext.pos + match.end())
    pcontext.pos += match.end()
    return (True, CommentParseEntry(comment))

def parse_next(pcontext):
    try:
        (r, comment) = parse_comment(pcontext)
        if pcontext.handle_comment:
            pcontext.handle_comment(pcontext, comment)
        return (r, comment)
    except NoParse:
        pass

    
    logger.debug("pos = %d", pcontext.pos)
    
#    cur_len = len(contents)
#    contents = contents.lstrip()
#    pcontext.pos += cur_len - len(contents)
    logger.debug("pos = %d", pcontext.pos)

    preinvoke_pos = pcontext.pos
    match = pcontext.match(INVOKEMACRO_PATTERN)
    if not match:
        return (False, None)
        #raise ParseError(pcontext._filename, pcontext.pos)
        
    word = match.group(1)
    logger.debug("word is %r", word)
#    logger.debug("incrementing position (%d) by %d (to %d)", pcontext.pos,
#                 match.end(), pcontext.pos + match.end())
#    pcontext.pos = pcontext.pos + match.end()
    
    cur_tuple = ()
    line = "" # fixme
    match = pcontext.match(r'\(')
    if match:
#    if len(line) and line[0] == '(':
#        logger.debug(word)
        
#        line = line[1:].lstrip()
#        pcontext.pos += 1
        
        isend = False
        cmd = word
        args = []
        #old_len = len(line)
        if cmd == "interface":
            (line, name, isend) = slurp_arg(pcontext)#, line)
            ary = []
            my_interface = Interface(name, pcontext._filename, preinvoke_pos)
            pcontext.interface[name] = my_interface
            args.append(name)
        if cmd == "template":
            (line, name, isend) = slurp_arg(pcontext)
            args.append(name)
            ary = []
            pcontext.template[name] = (pcontext._filename, pcontext.pos, ary)

        while not isend:
            (new_c, arg, isend) = slurp_arg(pcontext)
            logger.debug("Slurped argument (len %d): %s" %( len(arg), arg))
            args.append(arg)
            
            if arg is None:
                log_content(logger.debug, line)
                raise ParseError(file, pcontext.pos)

            line = new_c

#        logger.debug("incrementing position (%d) by %d (to %d)", pcontext.pos,
#                     old_len - len(line), pcontext.pos + (old_len - len(line)))
#        pcontext.pos += old_len - len(line)

        return (True, [cmd, args])
    else:
        logger.info("i am here with %s", word)

    return (True, None)


def parse_file(filename, interface, template, preserve_comments=True):
    pcontext = ParseContext(filename)
    pcontext.open()
    return parse(pcontext)


def parse(pcontext):
    file_ary = []
    r = True
    while r:
        (r, parse_entry) = parse_next(pcontext)
        if parse_entry:
            logger.debug("parse_entry = %r", parse_entry)
        file_ary.append(parse_entry)
    return file_ary
    

def main():
    import sys
    import json

    logging.basicConfig(level=logging.DEBUG)
    
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
        #json.dump(r, fp=sys.stdout, indent=4)
    
    for iface in interface.keys():
        (file, pos, ary) = interface[iface]
        print("I:%24s %s:%4d" % (iface, file, pos))

    for iface in template.keys():
        (file, pos, ary) = template[iface]
        print("T:%24s %s:%4d" % (iface, file, pos))

    
if __name__ == "__main__":
    main()
