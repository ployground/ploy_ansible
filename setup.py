from setuptools import setup
import os


here = os.path.abspath(os.path.dirname(__file__))
README = open(os.path.join(here, 'README.rst')).read()
HISTORY = open(os.path.join(here, 'HISTORY.rst')).read()


version = "1.3.2"


install_requires = [
    'setuptools',
    'ploy >= 1.0.0, < 2dev',
    'execnet']


# workaround for installing via buildout, as ansible<1.8.0
# violates its sandbox limitations
try:
    import ansible  # noqa
except ImportError:
    install_requires.append('ansible>=1.8.0,<2.dev0')


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
        'Programming Language :: Python :: 2.6',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 2 :: Only',
        'Topic :: System :: Installation/Setup',
        'Topic :: System :: Systems Administration'],
    include_package_data=True,
    zip_safe=False,
    packages=['ploy_ansible'],
    install_requires=install_requires,
    entry_points="""
        [ansible_paths]
        ploy_ansible = ploy_ansible:ansible_paths
        [ploy.plugins]
        ansible = ploy_ansible:plugin
    """)
