/**
 * @file    fsal_symlinks.c
 * @date    $Date: 2005/07/29 09:39:04 $
 * @brief   symlinks operations.
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
#include <string.h>
#include <unistd.h>

/** @fn fsal_status_t
 *	GPFSFSAL_readlink(struct fsal_obj_handle *dir_hdl,
 *			  const struct req_op_context *op_ctx,
 *			  char *link_content, size_t *link_len,
 *			  struct attrlist *link_attr)
 *  @brief Read the content of a symbolic link.
 *
 *  @param dir_hdl Handle of the link to be read.
 *  @param op_ctx Authentication context for the operation (user,...).
 *  @param link_content Fsal path struct where the link content is to be stored
 *  @param link_len Len of content buff. Out actual len of content.
 *  @param link_attr The post operation attributes of the symlink link.
 *                   As input, it defines the attributes that the caller
 *                   wants to retrieve (by positioning flags into this structure
 *                   and the output is built considering this input
 *                   (it fills the structure according to the flags it contains)
 *                   May be NULL.
 *
 *  @return Major error codes :
 *        - ERR_FSAL_NO_ERROR     (no error)
 *        - Another error code if an error occured.
 */
fsal_status_t
GPFSFSAL_readlink(struct fsal_obj_handle *dir_hdl,
		  const struct req_op_context *op_ctx, char *link_content,
		  size_t *link_len, struct attrlist *link_attr)
{
	fsal_status_t status = {ERR_FSAL_NO_ERROR, 0};
	struct gpfs_fsal_obj_handle *gpfs_hdl = NULL;
	struct gpfs_filesystem *gpfs_fs = NULL;

	/* sanity checks.
	 * note : link_attributes is optional.
	 */
	if (!dir_hdl || !op_ctx || !link_content)
		return fsalstat(ERR_FSAL_FAULT, 0);

	gpfs_hdl =
	    container_of(dir_hdl, struct gpfs_fsal_obj_handle, obj_handle);
	gpfs_fs = dir_hdl->fs->private;

	/* Read the link on the filesystem */
	status = fsal_readlink_by_handle(gpfs_fs->root_fd, gpfs_hdl->handle,
					 link_content, link_len);

	if (FSAL_IS_ERROR(status))
		return status;

	/* retrieves object attributes, if asked */
	if (link_attr) {
		status = GPFSFSAL_getattrs(op_ctx->fsal_export, gpfs_fs,
					   op_ctx, gpfs_hdl->handle, link_attr);

		/* On error, we set a flag in the returned attributes */
		if (FSAL_IS_ERROR(status)) {
			FSAL_CLEAR_MASK(link_attr->mask);
			FSAL_SET_MASK(link_attr->mask, ATTR_RDATTR_ERR);
		}
	}
	return status;
}

/**
 * FSAL_symlink:
 * Create a symbolic link.
 *
 * \param dir_hdl (input):
 *        Handle of the parent directory where the link is to be created.
 * \param p_linkname (input):
 *        Name of the link to be created.
 * \param p_linkcontent (input):
 *        Content of the link to be created.
 * \param p_context (input):
 *        Authentication context for the operation (user,...).
 * \param accessmode (ignored input):
 *        Mode of the link to be created.
 *        It has no sense in HPSS nor UNIX filesystems.
 * \param p_link_handle (output):
 *        Pointer to the handle of the created symlink.
 * \param link_attributes (optionnal input/output):
 *        Attributes of the newly created symlink.
 *        As input, it defines the attributes that the caller
 *        wants to retrieve (by positioning flags into this structure)
 *        and the output is built considering this input
 *        (it fills the structure according to the flags it contains).
 *        May be NULL.
 *
 * \return Major error codes :
 *        - ERR_FSAL_NO_ERROR     (no error)
 *        - Another error code if an error occured.
 */
fsal_status_t
GPFSFSAL_symlink(struct fsal_obj_handle *dir_hdl, const char *link_name,
		 const char *link_content, const struct req_op_context *op_ctx,
		 uint32_t accessmode, struct gpfs_file_handle *link_hdl,
		 struct attrlist *link_attr)
{

	fsal_status_t status = {ERR_FSAL_NO_ERROR, 0};
	struct gpfs_fsal_obj_handle *gpfs_hdl = NULL;
	struct gpfs_filesystem *gpfs_fs = NULL;
	int fd = -1;
	int errsv = 0;

	/* sanity checks.
	 * note : link_attributes is optional.
	 */
	if (!dir_hdl || !op_ctx || !link_hdl || !link_name || !link_content)
		return fsalstat(ERR_FSAL_FAULT, 0);

	gpfs_hdl = container_of(dir_hdl, struct gpfs_fsal_obj_handle,
				obj_handle);

	gpfs_fs = dir_hdl->fs->private;

	/* Tests if symlinking is allowed by configuration. */
	if (!op_ctx->fsal_export->exp_ops.fs_supports(op_ctx->fsal_export,
						      fso_symlink_support))
		return fsalstat(ERR_FSAL_NOTSUPP, 0);

	status = fsal_internal_handle2fd(gpfs_fs->root_fd, gpfs_hdl->handle,
					 &fd, O_RDONLY | O_DIRECTORY, 0);

	if (FSAL_IS_ERROR(status))
		return status;

	/* create the symlink on the filesystem using the credentials
	 * for proper ownership assignment.
	 */
	fsal_set_credentials(op_ctx->creds);
	if (symlinkat(link_content, fd, link_name) != 0) {
		errsv = errno;
		fsal_restore_ganesha_credentials();
		close(fd);
		return fsalstat(posix2fsal_error(errsv), errsv);
	}

	fsal_restore_ganesha_credentials();

	/* now get the associated handle, while there is a race, there is
	   also a race lower down  */
	status = fsal_internal_get_handle_at(fd, link_name, link_hdl);

	if (FSAL_IS_ERROR(status)) {
		close(fd);
		return status;
	}

	/* get attributes if asked */
	if (link_attr) {
		status = GPFSFSAL_getattrs(op_ctx->fsal_export, gpfs_fs,
					   op_ctx, link_hdl, link_attr);

		/* On error, we set a flag in the returned attributes */
		if (FSAL_IS_ERROR(status)) {
			FSAL_CLEAR_MASK(link_attr->mask);
			FSAL_SET_MASK(link_attr->mask, ATTR_RDATTR_ERR);
		} else if (link_attr->type != SYMBOLIC_LINK) {
			close(fd);
			return fsalstat(ERR_FSAL_EXIST, 0);
		}
	}

	close(fd);
	return status;
}
