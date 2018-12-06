import html
import os.path
from pathlib import Path
import sys
import os
import argparse
import logging
import logging.config
import selinux_misc.manage as manage
from io import StringIO
from selinux_misc.template_env import get_template_env

refpolicy_dir = '/home/user/j/jade/refpolicy'
policy_dir = os.path.join(refpolicy_dir, 'policy')
modules_dir = os.path.join(policy_dir, 'modules')
support_dir = os.path.join(policy_dir, 'support')

logger = logging.getLogger(__name__)

logging_config_dict = { 'version': 1, 'disable_existing_loggers': False, 'formatters': { 'standard': { 'format': '%(asctime)s [%(levelname)s] %(name)s: %(message)s' } }, 'handlers': { 'default': { 'level': 'DEBUG', 'formatter': 'standard', 'class': 'logging.StreamHandler' } }, 'loggers': { '': { 'handlers': ['default'], 'level': 'DEBUG', 'propagate': True }}}

def main():
#    logging.basicConfig(level=logging.WARNING)
    logging.config.dictConfig(logging_config_dict)
    arg_parser = argparse.ArgumentParser()
    arg_parser.add_argument('--output-dir', action='store')

    args = arg_parser.parse_args(sys.argv[1:])
    assert args.output_dir
    rules = manage.Rules("rules")
    my_manage = manage.Manage(args=args, rules=rules)

    iface_files = []
    te_files = []
    for root, dirs, files in os.walk(modules_dir):
        for file in files:

            fullpath = os.path.join(root, file)
            if not os.path.exists(fullpath):

                continue
            if file.endswith('.if'):
                iface_files.append(fullpath)
            elif file.endswith('.te'):
                te_files.append(fullpath)
            elif file.endswith('.spt'):
                iface_files.append(fullpath)

    env = get_template_env()
    assert iface_files
    context = "main"
    template = env.get_template('interface.html.jinja2')
    for iface_file in iface_files:
        logging.debug(iface_file)
        my_manage.process_input_file(main, iface_file)
        path = Path(iface_file)
        output_filename = os.path.join(args.output_dir, path.name + '.html')
        cur_pos = 0
        with open(iface_file, 'r') as fin:
#            in_text = fin.readlines().join('')
            with open(output_filename, 'w') as html_fout:
                fout = StringIO()
                for module in my_manage.modules:
                    for interface_name in module.get_interface_names():
                        my_interface = module._interface[interface_name]
                        fpos = my_interface.file_pos
                        to_read = fpos - cur_pos
                        cur_pos += to_read
                        logger.critical("%s %d", interface_name, fpos)
                        data = fin.read(to_read)
#                        logging.critical("%r", data)
                        data = html.escape(data)
                        num_written = fout.write(data)
                        assert num_written == len(data)
                        fout.write('<a name="%s">' % interface_name)

                html_fout.write(template.render(interfaces=module.get_interface_names(),
                                                body=fout.getvalue()))
                
        break
    
    

