from setuptools import setup

version = "0.1"

setup(
    version=version,
    description="A plugin for mr.awsome providing integration with Ansible.",
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
        'mr.awsome',
        'ansible'
    ],
    entry_points="""
        [mr.awsome.plugins]
        ansible = mr.awsome.ansible:plugin
    """)
