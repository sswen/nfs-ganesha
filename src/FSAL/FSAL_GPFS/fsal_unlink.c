/**
 * @file    fsal_unlink.c
 * @date    $Date: 2006/01/24 13:45:37 $
 * @brief   object removing function.
 *
 * vim:noexpandtab:shiftwidth=8:tabstop=8:
 *
 * Copyright CEA/DAM/DIF  (2008)
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

#include "fsal.h"
#include "fsal_internal.h"
#include "fsal_convert.h"
#include "gpfs_methods.h"
#include <unistd.h>

/** @fn fsal_status_t
 *	GPFSFSAL_unlink(struct fsal_obj_handle *dir_hdl, const char *object_name,
 *				      const struct req_op_context *op_ctx)
 *  @brief Remove a filesystem object .
 *
 *  @param dir_hdl  Handle of the parent directory of the object to be deleted.
 *  @param object_name Name of the object to be removed.
 *  @param op_ctx Authentication context for the operation (user,...).
 *
 *  @return Major error codes :
 *        - ERR_FSAL_NO_ERROR     (no error)
 *        - Another error code if an error occured.
 */

fsal_status_t
GPFSFSAL_unlink(struct fsal_obj_handle *dir_hdl, const char *object_name,
			      const struct req_op_context *op_ctx)
{
	struct gpfs_fsal_obj_handle *gpfs_hdl = NULL;
	struct gpfs_filesystem *gpfs_fs = NULL;
	gpfsfsal_xstat_t buffxstat = {0};
	fsal_status_t status = {ERR_FSAL_NO_ERROR, 0};

	/* sanity checks. */
	if (!dir_hdl || !op_ctx || !object_name)
		return fsalstat(ERR_FSAL_FAULT, 0);

	gpfs_hdl = container_of(dir_hdl, struct gpfs_fsal_obj_handle,
				obj_handle);
	gpfs_fs = dir_hdl->fs->private;

	/* get file metadata */
	status = fsal_internal_stat_name(gpfs_fs->root_fd, gpfs_hdl->handle,
					 object_name, &buffxstat.buffstat);
	if (FSAL_IS_ERROR(status))
		return status;

  /******************************
   * DELETE FROM THE FILESYSTEM *
   ******************************/
	fsal_set_credentials(op_ctx->creds);
	status = fsal_internal_unlink(gpfs_fs->root_fd, gpfs_hdl->handle,
				      object_name, &buffxstat.buffstat);
	fsal_restore_ganesha_credentials();

	return status;


}
