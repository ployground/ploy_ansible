# convenience makefile to run tests

version = 2.7

tests: bin/py.test
	bin/py.test ploy_ansible

bin/pserve bin/py.test: bin/python bin/pip bin/ansible setup.py
	bin/python setup.py dev

bin/ansible: bin/pip
	bin/pip install ansible

bin/python bin/pip:
	virtualenv-$(version) .

clean:
	git clean -fXd

.PHONY: clean tests
