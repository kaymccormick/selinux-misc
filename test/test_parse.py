import selinux_misc.parse as parse
import os
import os.path
import cProfile
from pytest import fixture
from unittest.mock import MagicMock
import logging

logger = logging.getLogger(__name__)

@fixture
def pcontext():
    return MagicMock(parse.ParseContext)
    
#def test_parse_comment(pcontext):
#    parse.parse_comment(pcontext)

def test_parse_1():
    r = parse.parse_file("data/us_heptet_cerberus_drupal.te", {}, {})
    print(repr(r))
    assert r
    
def test_parse_2():
    for root, dirs, files in os.walk("data"):
        for file in files:
            path = os.path.join(root, file)
            cProfile.run('import selinux_misc.parse; r = selinux_misc.parse.parse_file("%s", {}, {})' % path, 'restats')
            

def test_parse_3():
    path = "data/us_heptet_cerberus_httpd.te"
    context = parse.ParseContext(path)
    context.handle_comment = lambda context, comment: logger.critical("%r", comment)
    context.open()
    r = parse.parse(context)
