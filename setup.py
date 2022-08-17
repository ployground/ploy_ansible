import setuptools
import os


here = os.path.abspath(os.path.dirname(__file__))
README = open(os.path.join(here, 'README.rst')).read()
HISTORY = open(os.path.join(here, 'HISTORY.rst')).read()


version = "2.0.0"


classifiers = [
    'Environment :: Console',
    'Intended Audience :: System Administrators',
    'Programming Language :: Python :: 2.7',
    'Programming Language :: Python :: 3.7',
    'Programming Language :: Python :: 3.8',
    'Programming Language :: Python :: 3.9',
    'Programming Language :: Python :: 3.10',
    'Topic :: System :: Installation/Setup',
    'Topic :: System :: Systems Administration']

install_requires = [
    'execnet',
    'ploy >= 2.0.0',
    'ansible>=1.9,!=2.0.*,!=2.1.*,!=2.2.*,!=2.3.*;python_version<"3.0"',
    'ansible>=2.4;python_version>="3.0" and python_version<"3.10"',
    'ansible-core;python_version>="3.10"']


setuptools.setup(
    version=version,
    description="Plugin to integrate Ansible with ploy.",
    long_description=README + "\n\n" + HISTORY,
    name="ploy_ansible",
    author='Florian Schulze',
    author_email='florian.schulze@gmx.net',
    license="GPLv3",  # infected by code for ansible and playbook commands
    url='http://github.com/ployground/ploy_ansible',
    classifiers=classifiers,
    include_package_data=True,
    zip_safe=False,
    packages=['ploy_ansible'],
    install_requires=install_requires,
    python_requires='>=2.7, !=3.0.*, !=3.1.*, !=3.2.*, !=3.3.*, !=3.4.*, !=3.5.*, !=3.6.*',
    entry_points="""
        [ansible_paths]
        ploy_ansible = ploy_ansible:ansible_paths
        [ploy.plugins]
        ansible = ploy_ansible:plugin
    """)
