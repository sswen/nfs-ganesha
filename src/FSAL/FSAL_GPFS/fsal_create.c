/** @file fsal_create
 *  @brief GPFS FSAL Filesystem objects creation functions
 *
 * vim:noexpandtab:shiftwidth=8:tabstop=8:
 *
 */

#include "fsal.h"
#include "fsal_internal.h"
#include "fsal_convert.h"
#include "gpfs_methods.h"
#include <unistd.h>
#include <fcntl.h>
#include <fsal_api.h>
#include "FSAL/access_check.h"


/** @fn fsal_status_t
 *	GPFSFSAL_create(struct fsal_obj_handle *dir_hdl, const char *filename,
 *			const struct req_op_context *op_ctx,
 *			uint32_t accessmode, struct gpfs_file_handle *gpfs_fh,
 *			struct attrlist *fsal_attr)
 *  @param dir_hdl Handle of the parent directory where the file is to be created.
 *  @param filename Pointer to the name of the file to be created.
 *  @param op_ctx Authentication context for the operation (user,...).
 *  @param accessmode Mode for the file to be created.
 *  @param gpfs_fh Pointer to the handle of the created file.
 *  @param fsal_attr Attributes of the created file.
 *  @return ERR_FSAL_NO_ERROR on success, otherwise error
 *
 *  @brief Create a regular file.
 */
fsal_status_t
GPFSFSAL_create(struct fsal_obj_handle *dir_hdl, const char *filename,
		const struct req_op_context *op_ctx, uint32_t accessmode,
		struct gpfs_file_handle *gpfs_fh, struct attrlist *fsal_attr)
{
	fsal_status_t status = {ERR_FSAL_NO_ERROR, 0};
	mode_t unix_mode = 0;

	/* sanity checks.
	 * note : object_attributes is optional.
	 */
	if (!dir_hdl || !op_ctx || !gpfs_fh || !filename)
		return fsalstat(ERR_FSAL_FAULT, 0);

	/* convert fsal mode to unix mode. */
	unix_mode = fsal2unix_mode(accessmode);

	/* Apply umask */
	unix_mode &=
		~op_ctx->fsal_export->exp_ops.fs_umask(op_ctx->fsal_export);

	LogFullDebug(COMPONENT_FSAL, "Creation mode: 0%o", accessmode);

	/* call to filesystem */
	fsal_set_credentials(op_ctx->creds);
	status = fsal_internal_create(dir_hdl, filename, unix_mode | S_IFREG, 0,
				      gpfs_fh, NULL);
	fsal_restore_ganesha_credentials();
	if (FSAL_IS_ERROR(status))
		return status;

	/* retrieve file attributes */
	if (fsal_attr) {
		status = GPFSFSAL_getattrs(op_ctx->fsal_export,
				      dir_hdl->fs->private, op_ctx, gpfs_fh,
				      fsal_attr);

		/* on error, we set a special bit in the mask. */
		if (FSAL_IS_ERROR(status)) {
			FSAL_CLEAR_MASK(fsal_attr->mask);
			FSAL_SET_MASK(fsal_attr->mask, ATTR_RDATTR_ERR);
		}

	}

	return status;
}

/** @fn fsal_status_t
 *	GPFSFSAL_mkdir(struct fsal_obj_handle *dir_hdl, const char *dir_name,
 *		       const struct req_op_context *op_ctx,
 *		       uint32_t accessmode, struct gpfs_file_handle *gpfs_fh,
 *		       struct attrlist *fsal_attr)
 *  @param dir_hdl Handle of the parent directory
 *  @param dir_name Pointer to the name of the directory to be created.
 *  @param op_ctx Authentication context for the operation (user,...).
 *  @param accessmode Mode for the directory to be created.
 *  @param gpfs_fh Pointer to the handle of the created directory.
 *  @param fsal_attr Attributes of the created directory.
 *  @return ERR_FSAL_NO_ERROR on success, error otherwise
 *
 *  @brief Create a directory.
 */
fsal_status_t
GPFSFSAL_mkdir(struct fsal_obj_handle *dir_hdl, const char *dir_name,
	       const struct req_op_context *op_ctx, uint32_t accessmode,
	       struct gpfs_file_handle *gpfs_fh, struct attrlist *fsal_attr)
{
	fsal_status_t status = {ERR_FSAL_NO_ERROR, 0};
	mode_t unix_mode = 0;

	/* sanity checks.
	 * note : object_attributes is optional.
	 */
	if (!dir_hdl || !op_ctx || !gpfs_fh || !dir_name)
		return fsalstat(ERR_FSAL_FAULT, 0);

	/* convert FSAL mode to unix mode. */
	unix_mode = fsal2unix_mode(accessmode);

	/* Apply umask */
	unix_mode &=
		~op_ctx->fsal_export->exp_ops.fs_umask(op_ctx->fsal_export);

	/* build new entry path */
	/* creates the directory and get its handle */
	fsal_set_credentials(op_ctx->creds);
	status = fsal_internal_create(dir_hdl, dir_name, unix_mode | S_IFDIR, 0,
				      gpfs_fh, NULL);
	fsal_restore_ganesha_credentials();

	if (FSAL_IS_ERROR(status))
		return status;

	/* retrieve file attributes */
	if (fsal_attr) {
		status = GPFSFSAL_getattrs(op_ctx->fsal_export,
					   dir_hdl->fs->private,
					   op_ctx, gpfs_fh, fsal_attr);

		/* on error, we set a special bit in the mask. */
		if (FSAL_IS_ERROR(status)) {
			FSAL_CLEAR_MASK(fsal_attr->mask);
			FSAL_SET_MASK(fsal_attr->mask, ATTR_RDATTR_ERR);
		}
	}

	return status;
}

/** @fn fsal_status_t
 *	GPFSFSAL_link(struct fsal_obj_handle *dir_hdl,
 *		      struct gpfs_file_handle *gpfs_fh, const char *link_name,
 *		      const struct req_op_context *op_ctx,
 *		      struct attrlist *fsal_attr)
 *  @param dir_hdl Handle of the target object.
 *  @param gpfs_fh Pointer to the directory handle where hardlink is to be created.
 *  @param linkname Pointer to the name of the hardlink to be created.
 *  @param op_ctx Authentication context for the operation (user,...).
 *  @param fsal_attr The post_operation attributes of the linked object.
 *  @return ERR_FSAL_NO_ERROR on success, error otherwise
 *
 *  @brief Create a hardlink.
 */
fsal_status_t
GPFSFSAL_link(struct fsal_obj_handle *dir_hdl,
	      struct gpfs_file_handle *gpfs_fh, const char *linkname,
	      const struct req_op_context *op_ctx, struct attrlist *fsal_attr)
{
	fsal_status_t status = {ERR_FSAL_NO_ERROR, 0};
	struct gpfs_filesystem *gpfs_fs = NULL;
	struct gpfs_fsal_obj_handle *dest_dir = NULL;

	/* sanity checks.
	 * note : attributes is optional.
	 */
	if (!dir_hdl || !gpfs_fh || !op_ctx || !linkname)
		return fsalstat(ERR_FSAL_FAULT, 0);

	dest_dir =
	    container_of(dir_hdl, struct gpfs_fsal_obj_handle, obj_handle);
	gpfs_fs = dir_hdl->fs->private;

	/* Tests if hardlinking is allowed by configuration. */
	if (!op_ctx->fsal_export->exp_ops.
	    fs_supports(op_ctx->fsal_export,
			fso_link_support))
		return fsalstat(ERR_FSAL_NOTSUPP, 0);

	/* Create the link on the filesystem */
	fsal_set_credentials(op_ctx->creds);
	status = fsal_internal_link_fh(gpfs_fs->root_fd, gpfs_fh,
				       dest_dir->handle, linkname);
	fsal_restore_ganesha_credentials();

	if (FSAL_IS_ERROR(status))
		return status;

	/* optionnaly get attributes */
	if (fsal_attr) {
		status = GPFSFSAL_getattrs(op_ctx->fsal_export, gpfs_fs,
					   op_ctx, gpfs_fh, fsal_attr);

		/* on error, we set a special bit in the mask. */
		if (FSAL_IS_ERROR(status)) {
			FSAL_CLEAR_MASK(fsal_attr->mask);
			FSAL_SET_MASK(fsal_attr->mask, ATTR_RDATTR_ERR);
		}
	}

	return status;
}

/** @fn fsal_status_t
 *	GPFSFSAL_mknode(struct fsal_obj_handle *dir_hdl, const char *node_name,
 *			const struct req_op_context *op_ctx,
 *			uint32_t accessmode,
 *			mode_t node_type, fsal_dev_t *dev,
 *			struct gpfs_file_handle *gpfs_fh,
 *			struct attrlist *fsal_attr)
 *  @param dir_hdl Handle of the parent dir where the file is to be created.
 *  @param node_name Pointer to the name of the file to be created.
 *  @param op_ctx Authentication context for the operation (user,...).
 *  @param accessmode Mode for the file to be created.
 *  @param node_type Type of file to create.
 *  @param dev Device id of file to create.
 *  @param gpfs_fh Pointer to the handle of the created file.
 *  @param fsal_attr Attributes of the created file.
 *  @return ERR_FSAL_NO_ERROR on success, error otherwise
 *
 *  @brief Create a special object in the filesystem.
 */
fsal_status_t
GPFSFSAL_mknode(struct fsal_obj_handle *dir_hdl, const char *node_name,
		const struct req_op_context *op_ctx, uint32_t accessmode,
		mode_t node_type, fsal_dev_t *dev,
		struct gpfs_file_handle *gpfs_fh, struct attrlist *fsal_attr)
{
	fsal_status_t status = {ERR_FSAL_NO_ERROR, 0};
	mode_t unix_mode = 0;
	dev_t unix_dev = 0;

	/* sanity checks.
	 * note : link_attributes is optional.
	 */
	if (!dir_hdl || !op_ctx || !node_name)
		return fsalstat(ERR_FSAL_FAULT, 0);

	unix_mode = fsal2unix_mode(accessmode);

	/* Apply umask */
	unix_mode &=
		~op_ctx->fsal_export->exp_ops.fs_umask(op_ctx->fsal_export);

	switch (node_type) {
	case BLOCK_FILE:
		if (!dev)
			return fsalstat(ERR_FSAL_FAULT, 0);
		unix_mode |= S_IFBLK;
		unix_dev = (dev->major << 20) | (dev->minor & 0xFFFFF);
		break;

	case CHARACTER_FILE:
		if (!dev)
			return fsalstat(ERR_FSAL_FAULT, 0);
		unix_mode |= S_IFCHR;
		unix_dev = (dev->major << 20) | (dev->minor & 0xFFFFF);
		break;

	case SOCKET_FILE:
		unix_mode |= S_IFSOCK;
		break;

	case FIFO_FILE:
		unix_mode |= S_IFIFO;
		break;

	default:
		LogMajor(COMPONENT_FSAL, "Invalid node type in FSAL_mknode: %d",
			 node_type);
		return fsalstat(ERR_FSAL_INVAL, 0);
	}

	fsal_set_credentials(op_ctx->creds);
	status = fsal_internal_create(dir_hdl, node_name, unix_mode, unix_dev,
				      gpfs_fh, NULL);
	fsal_restore_ganesha_credentials();

	if (FSAL_IS_ERROR(status))
		return status;

	/* Fills the attributes if needed */
	if (fsal_attr) {
		status = GPFSFSAL_getattrs(op_ctx->fsal_export,
					   dir_hdl->fs->private,
					   op_ctx, gpfs_fh,
					   fsal_attr);

		/* on error, we set a special bit in the mask. */

		if (FSAL_IS_ERROR(status)) {
			FSAL_CLEAR_MASK(fsal_attr->mask);
			FSAL_SET_MASK(fsal_attr->mask, ATTR_RDATTR_ERR);
		}
	}

	return status;
}
