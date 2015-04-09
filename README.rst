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

``inventory``
  Lists all known groups and their associated hosts, including regular default groups, such as ``all`` but also implicit, ``ploy_ansible`` groups such as instances of a particular ``master`` (i.e. all ``ez-instances`` of an ``ez-master``) 

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

Using the `keyring <https://pypi.python.org/pypi/keyring/4.0/>`_ library, you can store the encryption key for the Ansible vault in your keychain.

The ``vault-password-source`` option is the id used in your keychain.
The id must be unique among all people who have to use the feature, as it is used as an identifier in their keychain.
If in doubt, use a speaking prefix and add a guid by running ``python -c "import uuid; print(uuid.uuid4().hex)"``.

If you want to rekey your files, you have to put the old id into the ``vault-password-old-source`` option and set a new id in ``vault-password-source``.
Just incrementing a number or appending a new guid is best.

Example:

.. code-block:: ini

    [ansible]
    vault-password-old-source = my-domain-deployment-0da2c8296f744c90a236721486dbd258
    vault-password-source = my-domain-deployment-042a98b666ec4e4e8e06de7d42688f3b

You can manage your key with the ``vault-key`` command.
For easy exchange with other developers, you can also export and import the key via gpg using the ``vault-key export`` and ``vault-key import`` commands.

Per instance
------------

``groups``
  Whitespace separated list of Ansible group names this instance should be added to in addition to the default ones.

``roles``
  Used by the ``configure`` command.
  This allows you to configure an instance by applying the whitespace separated roles.
  This is like creating a playbook which only specifies a host and a list of roles names.
  If the ``sudo`` option is set, it's also set for the generated playbook.

``playbook``
  Allows you to explicitly specify a playbook to use for this instance.
  If you need ``sudo``, then you have to add it yourself in that playbook.

Any option starting with ``ansible_`` is passed through to Ansible as is. This can be used for settings like ``ansible_python_interpreter``.

Any option starting with ``ansible-`` is stripped of the ``ansible-`` prefix and then passed through to Ansible.
This is the main way to set Ansible variables for use in playbooks and roles.

All other options are prefixed with ``ploy_`` and made available to Ansible.


Ansible inventory
=================

All instances in ``ploy.conf`` are available to Ansible via their **unique id**.

The variables for each instance are gathered from ``group_vars``, ``host_vars`` and the ``ploy.conf``.


Ansible lookup plugins
======================

The ``ploy_crypted`` lookup plugin can be used in playbooks to read the content of encrypted files.
This is another way to access encrypted data where you don't have to move that data into yml files.
An added benefit is, that the file is only decrypted when it is actually accessed.
If you run tasks filtered by tags and those tasks don't access the encrypted data, then it's not decrypted at all.

.. warning::
  This lookup plugin only works with files that are plain ascii or utf-8.
  It's a limitation caused by the way ansible handles variable substitution.


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
