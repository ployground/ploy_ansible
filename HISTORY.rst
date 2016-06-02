Changelog
=========

1.3.2 - 2016-06-02
------------------

* Don't add empty search path when no additional role or library paths are
  defined. This prevents the current working directory from being searched.
  [fschulze]


1.3.1 - 2015-09-03
------------------

* Update Ansible requirement to < 2.dev0. The upcoming 2.0.0 has way too many
  internal changes to be supported.
  [fschulze]

* Add hosts only once in Inventory.
  [fschulze]


1.3.0 - 2015-04-10
------------------

* Added handling of ``groups`` option of instances to allow definition of
  additional Ansible groups.
  [fschulze]

* Get host variables on demand instead of at startup. If you have many hosts
  with encrypted yml files, this speeds things up considerably in most cases.
  [fschulze]

* Fixes for changes in ansible 1.9.
  [fschulze]

* Added ``inventory`` command to list all known groups and their
  associated hosts.
  [fschulze]


1.2.4 - 2015-02-28
------------------

* Pass on the ``sudo`` setting if the ``roles`` option is used.
  [fschulze]


1.2.3 - 2015-02-28
------------------

* Fix sudo support for ansible > 1.6.
  [fschulze]

* Print warning when using an untested version of ansible.
  [fschulze]

* If ansible isn't installed, then require >= 1.8 as that doesn't violate
  the sandbox of buildout anymore.
  [fschulze]


1.2.2 - 2015-02-18
------------------

* Test and fixes for changes in ansible 1.8.
  [fschulze]


1.2.1 - 2015-01-06
------------------

* Limit Ansible to pre 1.8, as > 1.8 breaks stuff.
  [fschulze]


1.2.0 - 2014-10-27
------------------

* Always set ``ansible_ssh_user`` in inventory.
  [fschulze]

* Clear host and pattern cache after calling original Inventory.__init__ method.
  [fschulze]

* Add ``--extra-vars`` option to ``configure`` command.
  [witsch (Andreas Zeidler)]

* Provide ploy_crypted lookup plugin to load encrypted files into Ansible
  variables. Only ascii and utf8 encoded files will work.
  [fschulze]

* Expand Ansible variables in get_ansible_variables method.
  [fschulze]

* Support Ansible vault with safe key storage via keyring library, so you don't
  have to type it in or have it in an unprotected file.
  [fschulze]


1.1.0 - 2014-08-13
------------------

* Test and fixes for changes in ansible 1.7.
  [fschulze]

* Add verbosity argument to ``configure`` command.
  [fschulze]


1.0.0 - 2014-07-19
------------------

* Added documentation.
  [fschulze]


1.0b8 - 2014-07-15
------------------

* Add ansible as dependency if it can't be imported already.
  [fschulze]


1.0b7 - 2014-07-08
------------------

* Packaging and test fixes.
  [fschulze]


1.0b6 - 2014-07-04
------------------

* Use unique instance id to avoid issues.
  [fschulze]

* Renamed mr.awsome to ploy and mr.awsome.ansible to ploy_ansible.
  [fschulze]


1.0b5 - 2014-06-16
------------------

* Set user in playbook to the one from the config if it's not set already.
  [fschulze]

* Change default playbook directory from the aws.conf directory to it's parent.
  [fschulze]


1.0b4 - 2014-06-11
------------------

* Added ``playbook`` and ``roles`` config options for instances.
  [fschulze]

* Added ``has_playbook`` and ``configure`` methods to instances.
  [fschulze]

* Added before/after_ansible_configure hooks.
  [fschulze]


1.0b3 - 2014-06-09
------------------

* Use execnet for connections. There is only one ssh connection per host and
  it's reused for all commands.
  [fschulze]

* Make sure the playbook directory is always absolute.
  [fschulze]

* Prevent use of persistent ssh connections, as that easily results in
  connections to wrong jails because of the proxying. This makes ansible a lot
  slower at the moment.
  [fschulze]

* Add support for su and vault (ansible 1.5) as well as ``--force-handlers``
  (ansible 1.6).
  [fschulze]

* Removed ``ansible`` from install requirements. It won't install in a buildout
  so it needs to be installed in a virtualenv or via a system package.
  [fschulze]


1.0b2 - 2014-05-15
------------------

* Add ``configure`` command which is a stripped down variant of the
  ``playbook`` command with assumptions about the location of the yml file.
  [fschulze]

* Warn if a playbook is requested for a host that is not configured in the
  playbook hosts list.
  [fschulze]

* Allow mr.awsome plugins to add ansible variables.
  [fschulze]

* Inject the ansible paths sooner as they may not apply in some cases otherwise.
  [fschulze]

* Moved setuptools-git from setup.py to .travis.yml, it's only needed for
  releases and testing.
  [fschulze]


1.0b1 - 2014-03-24
------------------

* Initial release
  [fschulze]
