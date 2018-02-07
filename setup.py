from setuptools import setup
import os


here = os.path.abspath(os.path.dirname(__file__))
README = open(os.path.join(here, 'README.rst')).read()
HISTORY = open(os.path.join(here, 'HISTORY.rst')).read()


version = "2.0.0b2"


install_requires = [
    'ansible>=2.4',
    'execnet',
    'ploy >= 2.0.0b1']


setup(
    version=version,
    description="Plugin to integrate Ansible with ploy.",
    long_description=README + "\n\n" + HISTORY,
    name="ploy_ansible",
    author='Florian Schulze',
    author_email='florian.schulze@gmx.net',
    license="GPLv3",  # infected by code for ansible and playbook commands
    url='http://github.com/ployground/ploy_ansible',
    classifiers=[
        'Environment :: Console',
        'Intended Audience :: System Administrators',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 2 :: Only',
        'Topic :: System :: Installation/Setup',
        'Topic :: System :: Systems Administration'],
    include_package_data=True,
    zip_safe=False,
    packages=['ploy_ansible'],
    install_requires=install_requires,
    python_requires='>=2.7, <3.0',
    entry_points="""
        [ansible_paths]
        ploy_ansible = ploy_ansible:ansible_paths
        [ploy.plugins]
        ansible = ploy_ansible:plugin
    """)
