from ansible import utils, errors
import os


class LookupModule(object):
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
