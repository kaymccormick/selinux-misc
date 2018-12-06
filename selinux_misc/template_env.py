from jinja2 import Environment, PackageLoader

def get_template_env():
    env = Environment(loader=PackageLoader('selinux_misc', 'templates'),
                      trim_blocks=True,
                      lstrip_blocks=True,
                      autoescape=False)
    return env
