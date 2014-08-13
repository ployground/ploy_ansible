from setuptools import setup
import os


here = os.path.abspath(os.path.dirname(__file__))
README = open(os.path.join(here, 'README.rst')).read()


version = "1.1.0"


install_requires = [
    'setuptools',
    'ploy >= 1.0.0',
    'execnet']


# workaround for installing via buildout, as ansible
# violates its sandbox limitations
try:
    import ansible  # noqa
except ImportError:
    install_requires.append('ansible')


setup(
    version=version,
    description="Plugin to integrate Ansible with ploy.",
    long_description=README + "\n\n",
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
        [ploy.plugins]
        ansible = ploy_ansible:plugin
    """)
