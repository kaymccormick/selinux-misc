import os

from setuptools import setup, find_packages

here = os.path.abspath(os.path.dirname(__file__))

requires = [
]

tests_require = [
    'pytest',
]

setup(
    name='selinux-misc',
    version='0.1',
    description='SELinux miscellaneous tools',
    classifiers=[
        'Programming Language :: Python',
        'Topic :: Security',
        'Operating System :: POSIX :: Linux',
        'Topic :: System :: Operating System Kernels :: Linux',
        'Topic :: System :: Systems Administration',
        'Development Status :: 2 - Pre-Alpha',
        'Environment :: Console',
        'Intended Audience :: Developers',
        'Intended Audience :: Information Technology',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: MIT License',
    ],
    author='Kay McCormick',
    author_email='kay@kaymccormick.com',
    url='',
    keywords='selinux linux security',
    packages=find_packages(exclude=["node_modules"]),
    include_package_data=True,
    zip_safe=False,
    extras_require={
        'testing': tests_require,
    },
    install_requires=requires,
    entry_points={
        'console_scripts': [
            'selmisc-manage = selinux_misc.manage:main',
            'selmisc-hypertext = selinux_misc.hypertext:main',
        ],
    },
)
