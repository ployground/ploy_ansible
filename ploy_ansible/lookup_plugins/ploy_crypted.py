from ansible.module_utils._text import to_text
from ansible.plugins.lookup import LookupBase


class LookupModule(LookupBase):
    def run(self, terms, variables, **kwargs):

        ret = []

        for term in terms:
            lookupfile = self.find_file_in_search_path(variables, 'files', term)
            if lookupfile:
                (b_contents, show_data) = self._loader._get_file_contents(lookupfile)
                vaultlib = variables['_ploy_instance'].get_vault_lib()
                if vaultlib.is_encrypted(b_contents):
                    b_contents = vaultlib.decrypt(b_contents)
                b_contents = to_text(b_contents, errors='surrogate_or_strict')
                ret.append(b_contents)

        return ret
