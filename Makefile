SUBDIRS = src

include buildsys.mk
include extra.mk

install-extra:
	i=packages/ObjOpenSSL; \
	${INSTALL_STATUS}; \
	if ${INSTALL} -m 644 $$i ${DESTDIR}$$(${OBJFW_CONFIG} --packages-dir)/ObjOpenSSL; then \
		${INSTALL_OK}; \
	else \
		${INSTALL_FAILED}; \
	fi

uninstall-extra:
	i=packages/ObjOpenSSL; \
	if test -f ${DESTDIR}$$(${OBJFW_CONFIG} --packages-dir)/ObjOpenSSL; then \
		if rm -f ${DESTDIR}$$(${OBJFW_CONFIG} --packages-dir)/ObjOpenSSL; then \
			${DELETE_OK}; \
		else \
			${DELETE_FAILED}; \
		fi \
	fi
