from setuptools import setup
import os


here = os.path.abspath(os.path.dirname(__file__))
README = open(os.path.join(here, 'README.rst')).read()


version = "1.0b6"


setup(
    version=version,
    description="A plugin for ploy providing integration with Ansible.",
    long_description=README + "\n\n",
    name="ploy_ansible",
    author='Florian Schulze',
    author_email='florian.schulze@gmx.net',
    license="GPLv3",  # infected by code for ansible and playbook commands
    url='http://github.com/ployground/ploy_ansible',
    include_package_data=True,
    zip_safe=False,
    packages=['ploy_ansible'],
    install_requires=[
        'setuptools',
        'ploy >= 1.0rc9',
        'execnet'
    ],
    entry_points="""
        [ploy.plugins]
        ansible = ploy_ansible:plugin
    """)
