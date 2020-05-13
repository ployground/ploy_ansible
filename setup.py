import setuptools
import os
import sys


here = os.path.abspath(os.path.dirname(__file__))
README = open(os.path.join(here, 'README.rst')).read()
HISTORY = open(os.path.join(here, 'HISTORY.rst')).read()


version = "2.0.0b6"


classifiers = [
    'Environment :: Console',
    'Intended Audience :: System Administrators',
    'Programming Language :: Python :: 2.7',
    'Topic :: System :: Installation/Setup',
    'Topic :: System :: Systems Administration']

extras_require = {}

install_requires = [
    'execnet',
    'ploy >= 2.0.0b3']


def get_environment_marker_support_level():
    """
    Tests how well setuptools supports PEP-426 environment marker.

    The first known release to support it is 0.7 (and the earliest on PyPI seems to be 0.7.2
    so we're using that), see: https://setuptools.readthedocs.io/en/latest/history.html#id350

    The support is later enhanced to allow direct conditional inclusions inside install_requires,
    which is now recommended by setuptools. It first appeared in 36.2.0, went broken with 36.2.1, and
    again worked since 36.2.2, so we're using that. See:
    https://setuptools.readthedocs.io/en/latest/history.html#v36-2-2
    https://github.com/pypa/setuptools/issues/1099

    References:

    * https://wheel.readthedocs.io/en/latest/index.html#defining-conditional-dependencies
    * https://www.python.org/dev/peps/pep-0426/#environment-markers
    * https://setuptools.readthedocs.io/en/latest/setuptools.html#declaring-platform-specific-dependencies
    """
    import pkg_resources
    try:
        version = pkg_resources.parse_version(setuptools.__version__)
        if version >= pkg_resources.parse_version('36.2.2'):
            return 2
        if version >= pkg_resources.parse_version('0.7.2'):
            return 1
    except Exception as exc:
        sys.stderr.write("Could not test setuptool's version: %s\n" % exc)
    return 0


if get_environment_marker_support_level() >= 2:
    install_requires.append('ansible>=1.9,!=2.0.*,!=2.1.*,!=2.2.*,!=2.3.*;python_version<"3.0"')
    install_requires.append('ansible>=2.4;python_version>"3.0"')
    classifiers.extend([
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7'])
elif get_environment_marker_support_level() == 1:
    extras_require[':python_version<"3.0"'] = ['ansible>=1.9,!=2.0.*,!=2.1.*,!=2.2.*,!=2.3.*']
    extras_require[':python_version>"3.0"'] = ['ansible>=2.4']
    classifiers.extend([
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7'])
else:
    if sys.version_info < (3, 0):
        install_requires.append('ansible>=1.9,!=2.0.*,!=2.1.*,!=2.2.*,!=2.3.*')
    else:
        install_requires.append('ansible>=2.4')


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
    extras_require=extras_require,
    python_requires='>=2.7, !=3.0.*, !=3.1.*, !=3.2.*, !=3.3.*, !=3.4.*',
    entry_points="""
        [ansible_paths]
        ploy_ansible = ploy_ansible:ansible_paths
        [ploy.plugins]
        ansible = ploy_ansible:plugin
    """)
