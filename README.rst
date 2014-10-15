Overview
========

The ploy_ansible plugin provides integration of `Ansible`_ with `ploy`_.
It automatically builds an `inventory`_ and provides a custom connection plugin.

.. _Ansible: http://docs.ansible.com
.. _ploy: https://github.com/ployground
.. _inventory: http://docs.ansible.com/intro_inventory.html


Installation
============

ploy_ansible is best installed with easy_install, pip or with zc.recipe.egg in a buildout.


Commands
========

The plugin adds the following commands to ploy.

``configure``
  Configures an instance.
  There are three ways to specify how to configure an instance.
  Applying the roles given by the ``roles`` option of an instance, a playbook set by the ``playbook`` option or a playbook with the unique name of the instance found in the ``playbooks-directory``.
  Using ``roles`` or a playbook is mutually exclusive.
  If you specify a playbook and there is also a playbook in the default location, you will get a warning.

``ansible``
  Runs an Ansible command.
  This basically reflects the ``ansible`` script of Ansible.

``playbook``
  Applies a playbook.
  This basically reflects the ``ansible-playbook`` script of Ansible.

``vault``
  Manages file encryption.
  This basically reflects the ``ansible-vault`` script of Ansible, but handles the encryption key source via ``ploy.conf``.

``vault-key``
  Manages the vault key.


Options
=======

Global
------

playbooks-directory
~~~~~~~~~~~~~~~~~~~

The ``playbooks-directory`` option of the ``ansible`` section allows you to specify the directory where playbooks, roles, host_vars etc are looked up.
If you specify a relative path, then it's always relative to the ``ploy.conf`` directory.
If you have a structure like this::

    project
    |-- deployment
    | |-- roles
    | |-- host_vars
    |
    |-- etc
      |-- ploy.conf

Then you would put the following into your ``ploy.conf``::

    [ansible]
    playbooks-directory = ../deployment

By default it is set to the parent directory of the directory the ``ploy.conf`` is located at like this::

    project
    |-- roles
    |-- host_vars
    |-- etc
      |-- ploy.conf


vault-password-source
~~~~~~~~~~~~~~~~~~~~~

The ``vault-password-source`` option allows you to set where the encryption key for the Ansible vault comes from.

You specify the kind of source separated by a colon from the id you want to use.

The id must be unique among all people who have to use the feature, as it is used as an identifier in their keychain.
If in doubt, use a speaking prefix and add a guid by running ``python -c "import uuid; print(uuid.uuid4().hex)"``.

These sources are supported:

``keyring``
  Use the `keyring <https://pypi.python.org/pypi/keyring/4.0/>`_ library to store the key.

If you want to rekey your files, you have to put the old id into the ``vault-password-old-source`` option and set a new id in ``vault-password-source``.
Just incrementing a number or appending a new guid is best.

Example:

.. code-block:: ini

    [ansible]
    vault-password-old-source = keyring:my-domain-deployment-0da2c8296f744c90a236721486dbd258
    vault-password-source = keyring:my-domain-deployment-042a98b666ec4e4e8e06de7d42688f3b


Per instance
------------

``roles``
  Used by the ``configure`` command.
  This allows you to configure an instance by applying the whitespace separated roles.
  This is like creating a playbook which only specifies a host and a list of roles names.

``playbook``
  Allows you to explicitly specify a playbook to use for this instance.

Any option starting with ``ansible_`` is passed through to Ansible as is. This can be used for settings like ``ansible_python_interpreter``.

Any option starting with ``ansible-`` is stripped of the ``ansible-`` prefix and then passed through to Ansible.
This is the main way to set Ansible variables for use in playbooks and roles.

All other options are prefixed with ``ploy_`` and made available to Ansible.


Ansible inventory
=================

All instances in ``ploy.conf`` are available to Ansible via their **unique id**.

The variables for each instance are gathered from ``group_vars``, ``host_vars`` and the ``ploy.conf``.


API usage
=========

On the Python side, each ploy instance gains the following methods:

``apply_playbook(self, playbook, *args, **kwargs)``
  Applies the ``playbook`` to the instance.

``has_playbook``
  Return ``True`` if the instance has either of the ``roles`` or a playbook option set.

``get_playbook(*args, **kwargs)``
  Returns an instance of the Ansible internal ``PlayBook`` class.
  This is either from a file (from ``playbook`` option or the playbook kwarg), or dynamically generated from the ``roles`` option.

``configure(*args, **kwargs)``
  Configures the instance with the same semantics as the ``configure`` command.

``get_ansible_variables``
  Returns the Ansible variables from the inventory.
  This does not include *facts*, as it doesn't connect to the instance.
  This is particularly useful in Fabric scripts.

``get_vault_lib``
  Returns a readily usable Ansible VaultLib class.
  Use the ``encrypt`` and ``decrypt`` methods do encrypt/decrypt strings.


Changelog
=========

1.2.0 - Unreleased
------------------

* Add ``--extra-vars`` option to ``configure`` command.
  [witsch (Andreas Zeidler)]

* Provide ploy_crypted lookup plugin to load encrypted files into Ansible
  variables. Only ascii and utf8 encoded files will work.
  [fschulze]

* Expand Ansible variables in get_ansible_variables method.
  [fschulze]

* Support Ansible vault with safe key storage.
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
