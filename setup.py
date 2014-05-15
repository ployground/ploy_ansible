from setuptools import setup
import os


here = os.path.abspath(os.path.dirname(__file__))
README = open(os.path.join(here, 'README.rst')).read()


version = "1.0b2"


setup(
    version=version,
    description="A plugin for mr.awsome providing integration with Ansible.",
    long_description=README + "\n\n",
    name="mr.awsome.ansible",
    author='Florian Schulze',
    author_email='florian.schulze@gmx.net',
    url='http://github.com/fschulze/mr.awsome.ansible',
    include_package_data=True,
    zip_safe=False,
    packages=['mr'],
    namespace_packages=['mr'],
    install_requires=[
        'setuptools',
        'mr.awsome >= 1.0rc2',
        'ansible'
    ],
    entry_points="""
        [mr.awsome.plugins]
        ansible = mr.awsome_ansible:plugin
    """)
