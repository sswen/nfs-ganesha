/**
 * @file    fsal_lookup.c
 * @date    $Date: 2006/01/24 13:45:37 $
 * @brief   Lookup operations.
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

#include <string.h>
#include "fsal.h"
#include "FSAL/fsal_commonlib.h"
#include "fsal_internal.h"
#include "fsal_convert.h"
#include "gpfs_methods.h"

/** @fn fsal_status_t
 *	GPFSFSAL_lookup(const struct req_op_context *op_ctx,
 *			struct fsal_obj_handle *dir_hdl, const char *filename,
 *			struct attrlist *fsal_attr,
 *			struct gpfs_file_handle *gpfs_fh,
 *			struct fsal_filesystem **new_fs)
 *  @brief Looks up for an object into a directory.
 *
 *        if parent handle and filename are NULL,
 *        this retrieves root's handle.
 *
 *  @param op_ctx Authentication context for the operation (user,...).
 *  @param dir_hdl Handle of the parent directory to search the object in.
 *  @param filename The name of the object to find.
 *  @param fsal_attr Pointer to the attributes of the object we found.
 *  @param gpfs_fh The handle of the object corresponding to filename.
 *  @param new_fs New FS
 *
 *  @return - ERR_FSAL_NO_ERROR, if no error.
 *          - Another error code else.
 */
fsal_status_t
GPFSFSAL_lookup(const struct req_op_context *op_ctx,
		struct fsal_obj_handle *dir_hdl, const char *filename,
		struct attrlist *fsal_attr, struct gpfs_file_handle *gpfs_fh,
		struct fsal_filesystem **new_fs)
{
	struct gpfs_fsal_obj_handle *parent_hdl = NULL;
	struct gpfs_filesystem *gpfs_fs = NULL;
	struct fsal_fsid__ fsid = {0};
	fsal_status_t status = {ERR_FSAL_NO_ERROR, 0};
	int parent_fd = -1;

	if (!dir_hdl || !filename)
		return fsalstat(ERR_FSAL_FAULT, 0);

	assert(*new_fs == dir_hdl->fs);

	parent_hdl = container_of(dir_hdl, struct gpfs_fsal_obj_handle,
				  obj_handle);
	gpfs_fs = dir_hdl->fs->private;

	status = fsal_internal_handle2fd_at(gpfs_fs->root_fd,
					    parent_hdl->handle, &parent_fd,
					    O_RDONLY, 0);
	if (FSAL_IS_ERROR(status))
		return status;

	/* Be careful about junction crossing, symlinks, hardlinks,... */
	switch (dir_hdl->type) {
	case DIRECTORY:
		break;
	case REGULAR_FILE:
	case SYMBOLIC_LINK:
		/* not a directory */
		close(parent_fd);
		return fsalstat(ERR_FSAL_NOTDIR, 0);
	default:
		close(parent_fd);
		return fsalstat(ERR_FSAL_SERVERFAULT, 0);
	}

	status = fsal_internal_get_handle_at(parent_fd, filename, gpfs_fh);
	if (FSAL_IS_ERROR(status)) {
		close(parent_fd);
		return status;
	}

	/* In order to check XDEV, we need to get the fsid from the handle.
	 * We need to do this before getting attributes in order to have tthe
	 * correct gpfs_fs to pass to GPFSFSAL_getattrs. We also return
	 * the correct fs to the caller.
	 */
	gpfs_extract_fsid(gpfs_fh, &fsid);

	if (fsid.major != parent_hdl->attributes.fsid.major) {
		/* XDEV */
		*new_fs = lookup_fsid(&fsid, GPFS_FSID_TYPE);
		if (*new_fs == NULL) {
			LogDebug(COMPONENT_FSAL,
				 "Lookup of %s crosses filesystem boundary to unknown file system fsid=0x%016"
				 PRIx64".0x%016"PRIx64, filename, fsid.major,
				 fsid.minor);
			return fsalstat(ERR_FSAL_XDEV, EXDEV);
		}

		if ((*new_fs)->fsal != dir_hdl->fsal) {
			LogDebug(COMPONENT_FSAL,
				 "Lookup of %s crosses filesystem boundary to file system %s into FSAL %s",
				 filename, (*new_fs)->path,
				 (*new_fs)->fsal != NULL ?
					(*new_fs)->fsal->name : "(none)");
			return fsalstat(ERR_FSAL_XDEV, EXDEV);
		} else {
			LogDebug(COMPONENT_FSAL,
				 "Lookup of %s crosses filesystem boundary to file system %s",
				 filename, (*new_fs)->path);
		}
		gpfs_fs = (*new_fs)->private;
	}

	/* get object attributes */
	if (fsal_attr) {
		fsal_attr->mask =
		    op_ctx->fsal_export->exp_ops.fs_supported_attrs(
			op_ctx->fsal_export);
		status = GPFSFSAL_getattrs(op_ctx->fsal_export, gpfs_fs,
					   op_ctx, gpfs_fh, fsal_attr);
		if (FSAL_IS_ERROR(status)) {
			FSAL_CLEAR_MASK(fsal_attr->mask);
			FSAL_SET_MASK(fsal_attr->mask, ATTR_RDATTR_ERR);
		}
	}

	close(parent_fd);

	return status;
}
