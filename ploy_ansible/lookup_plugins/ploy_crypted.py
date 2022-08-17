try:
    from ansible.module_utils._text import to_text
    from ansible.plugins.lookup import LookupBase

    class LookupModule(LookupBase):
        def run(self, terms, variables, **kwargs):
            from ploy_ansible.inventory import InventoryManager

            ret = []

            for term in terms:
                lookupfile = self.find_file_in_search_path(variables, 'files', term)
                if lookupfile:
                    (b_contents, show_data) = self._loader._get_file_contents(lookupfile)
                    ctrl = InventoryManager._ploy_ctrl
                    instance = ctrl.instances[variables['_ploy_instance_uid']]
                    vaultlib = instance.get_vault_lib()
                    if vaultlib.is_encrypted(b_contents):
                        b_contents = vaultlib.decrypt(b_contents)
                    b_contents = to_text(b_contents, errors='surrogate_or_strict')
                    ret.append(b_contents)

            return ret
except ImportError:
    from ansible import utils, errors
    import os

    class LookupModule:
        def __init__(self, basedir=None, **kwargs):
            self.basedir = basedir

        def run(self, terms, inject=None, **kwargs):
            terms = utils.listify_lookup_plugin_terms(terms, self.basedir, inject)
            ret = []
            if not isinstance(terms, list):
                terms = [terms]
            for term in terms:
                basedir_path = utils.path_dwim(self.basedir, term)
                relative_path = None
                playbook_path = None
                if '_original_file' in inject:
                    relative_path = utils.path_dwim_relative(inject['_original_file'], 'files', term, self.basedir, check=False)
                if 'playbook_dir' in inject:
                    playbook_path = os.path.join(inject['playbook_dir'], term)
                for path in (basedir_path, relative_path, playbook_path):
                    if path and os.path.exists(path):
                        vaultlib = inject['_ploy_instance'].get_vault_lib()
                        with open(path) as f:
                            data = f.read()
                        if vaultlib.is_encrypted(data):
                            data = vaultlib.decrypt(data)
                        try:
                            data = data.decode('utf8')
                        except UnicodeDecodeError as e:
                            raise errors.AnsibleError("UnicodeDecodeError encrypted file lookup, only ascii and utf8 supported: %s\n%s" % (term, e))
                        ret.append(data)
                        break
                else:
                    raise errors.AnsibleError("could not locate encrypted file in lookup: %s" % term)
            return ret
