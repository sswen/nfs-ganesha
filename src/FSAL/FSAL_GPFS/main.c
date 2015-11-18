/** @file main.c
 *  @brief GPFS FSAL module core functions
 *
 * vim:noexpandtab:shiftwidth=8:tabstop=8:
 *
 * Copyright (C) Panasas Inc., 2011
 * Author: Jim Lieb jlieb@panasas.com
 *
 * contributeur : Philippe DENIEL   philippe.deniel@cea.fr
 *                Thomas LEIBOVICI  thomas.leibovici@cea.fr
 *
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 3 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301 USA
 *
 * -------------
 */

#include <libgen.h>		/* used for 'dirname' */
#include <pthread.h>
#include <string.h>
#include <sys/types.h>
#include "fsal.h"
#include "fsal_internal.h"
#include "FSAL/fsal_init.h"
#include "gpfs_methods.h"
#include "gpfs_main.h"

/** @fn struct fsal_staticfsinfo_t *gpfs_staticinfo(struct fsal_module *hdl)
 *  @brief private helper for export object
 *  @param hdl handle to fsal_module
 */
struct fsal_staticfsinfo_t *gpfs_staticinfo(struct fsal_module *hdl)
{
	struct gpfs_fsal_module *gpfs_me =
		container_of(hdl, struct gpfs_fsal_module, fsal);

	return &gpfs_me->fs_info;
}

/** @fn static int
 *      log_to_gpfs(log_header_t headers, void *private, log_levels_t level,
 *	struct display_buffer *buffer, char *compstr, char *message)
 *  @brief Log to gpfs
 */
static int
log_to_gpfs(log_header_t headers, void *private, log_levels_t level,
	    struct display_buffer *buffer, char *compstr, char *message)
{
	struct trace_arg targ = {0};

	if (level <= 0)
		return 0;

	targ.level = level;
	targ.len = strlen(compstr);
	targ.str = compstr;

	return gpfs_ganesha(OPENHANDLE_TRACE_ME, &targ);
}

/** @fn static fsal_status_t init_config(struct fsal_module *fsal_hdl,
 *	config_file_t config_struct, struct config_error_type *err_type)
 *  @brief must be called with a reference taken (via lookup_fsal)
 */
static fsal_status_t init_config(struct fsal_module *fsal_hdl,
				 config_file_t config_struct,
				 struct config_error_type *err_type)
{
	int rc = 0;
	struct gpfs_fsal_module *gpfs_me =
	    container_of(fsal_hdl, struct gpfs_fsal_module, fsal);

	gpfs_me->fs_info = default_gpfs_info;  /** get a copy of the defaults */

	(void) load_config_from_parse(config_struct, &gpfs_param,
				      &gpfs_me->fs_info, true, err_type);

	if (!config_error_is_harmless(err_type))
		goto facility_error;

	display_fsinfo(&gpfs_me->fs_info);

	LogFullDebug(COMPONENT_FSAL,
		     "Supported attributes constant = 0x%" PRIx64,
		     (uint64_t) GPFS_SUPPORTED_ATTRIBUTES);
	LogFullDebug(COMPONENT_FSAL,
		     "Supported attributes default = 0x%" PRIx64,
		     default_gpfs_info.supported_attrs);
	LogDebug(COMPONENT_FSAL,
		 "FSAL INIT: Supported attributes mask = 0x%" PRIx64,
		 gpfs_me->fs_info.supported_attrs);

	rc = create_log_facility(myname, log_to_gpfs,
				 NIV_FULL_DEBUG, LH_COMPONENT, NULL);
	if (rc != 0) {
		LogCrit(COMPONENT_FSAL,
			"Could not create GPFS logger (%s)", strerror(-rc));
		goto facility_error;
	}

	if (gpfs_me->fs_info.fsal_trace) {
		rc = enable_log_facility(myname);
		if (rc != 0) {
			LogCrit(COMPONENT_FSAL,
				"Could not enable GPFS logger (%s)",
				strerror(-rc));
			goto facility_error;
		}
	} else {
		rc = disable_log_facility(myname);
		if (rc != 0) {
			LogCrit(COMPONENT_FSAL,
				"Could not disable GPFS logger (%s)",
				strerror(-rc));
			goto facility_error;
		}
	}

	return fsalstat(ERR_FSAL_NO_ERROR, 0);

facility_error:
	return fsalstat(ERR_FSAL_INVAL, 0);

}

int gpfs_max_fh_size;

/** @fn MODULE_INIT void gpfs_init(void)
 *  @brief  Module initialization.
 *
 *  Called by dlopen() to register the module
 *  keep a private pointer to me in myself
 */
MODULE_INIT void gpfs_init(void)
{
	struct fsal_module *myself = &GPFS.fsal;

	if (nfs_param.core_param.short_file_handle)
		gpfs_max_fh_size = OPENHANDLE_SHORT_HANDLE_LEN;
	else
		gpfs_max_fh_size = OPENHANDLE_HANDLE_LEN;

	if (register_fsal(myself, myname, FSAL_MAJOR_VERSION,
			  FSAL_MINOR_VERSION, FSAL_ID_GPFS) != 0) {
		fprintf(stderr, "GPFS module failed to register");
		return;
	}

	/** Set up module operations */
	myself->m_ops.fsal_pnfs_ds_ops = pnfs_ds_ops_init;
	myself->m_ops.create_export = gpfs_create_export;
	myself->m_ops.init_config = init_config;
	myself->m_ops.getdeviceinfo = getdeviceinfo;
	myself->m_ops.fs_da_addr_size = fs_da_addr_size;
}

/** @fn MODULE_FINI void gpfs_unload(void)
 *  @brief unload module
 */
MODULE_FINI void gpfs_unload(void)
{
	release_log_facility(myname);

	if (unregister_fsal(&GPFS.fsal) != 0)
		fprintf(stderr, "GPFS module failed to unregister");
}
