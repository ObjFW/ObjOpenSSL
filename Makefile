SUBDIRS = src

include buildsys.mk
include extra.mk

install-extra:
	i=ObjOpenSSL.oc; \
	packagesdir="${DESTDIR}$$(${OBJFW_CONFIG} --packages-dir)"; \
	${INSTALL_STATUS}; \
	if ${MKDIR_P} $$packagesdir && ${INSTALL} -m 644 $$i $$packagesdir/$$i; then \
		${INSTALL_OK}; \
	else \
		${INSTALL_FAILED}; \
	fi

uninstall-extra:
	i=ObjOpenSSL.oc; \
	packagesdir="${DESTDIR}$$(${OBJFW_CONFIG} --packages-dir)"; \
	if test -f $$packagesdir/$$i; then \
		if rm -f $$packagesdir/$$i; then \
			${DELETE_OK}; \
		else \
			${DELETE_FAILED}; \
		fi \
	fi; \
	rmdir $$packagesdir >/dev/null 2>&1 || true
