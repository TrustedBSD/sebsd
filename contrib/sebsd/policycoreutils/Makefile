SUBDIRS=setfiles semanage load_policy newrole run_init restorecon restorecond secon audit2allow audit2why scripts sestatus semodule_package semodule semodule_link semodule_expand semodule_deps setsebool po

all install relabel clean indent:
	@for subdir in $(SUBDIRS); do \
		(cd $$subdir && $(MAKE) $@) || exit 1; \
	done

test:
