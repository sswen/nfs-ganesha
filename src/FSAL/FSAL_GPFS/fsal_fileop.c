/*
 * @file    fsal_fileop.c
 * @date    $Date: 2006/01/17 14:20:07 $
 * @brief   Files operations.
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
#include "FSAL/access_check.h"

/**
 * FSAL_open:
 * Open a regular file for reading/writing its data content.
 *
 * @param obj_hdl Handle of the file to be read/modified.
 * @param op_ctx Authentication context for the operation (user,...).
 * @param openflags Flags that indicates behavior for file opening and access.
 *        This is an inclusive OR of the following values
 *        ( such of them are not compatible) :
 *        - FSAL_O_RDONLY: opening file for reading only.
 *        - FSAL_O_RDWR: opening file for reading and writing.
 *        - FSAL_O_WRONLY: opening file for writting only.
 *        - FSAL_O_APPEND: always write at the end of the file.
 *        - FSAL_O_TRUNC: truncate the file to 0 on opening.
 * @param file_desc The file descriptor to be used for FSAL_read/write operations.
 * @param fsal_attr Post operation attributes.
 *        As input, it defines the attributes that the caller
 *        wants to retrieve (by positioning flags into this structure)
 *        and the output is built considering this input
 *        (it fills the structure according to the flags it contains).
 *
 * @return ERR_FSAL_NO_ERROR on success, error otherwise
 */
fsal_status_t
GPFSFSAL_open(struct fsal_obj_handle *obj_hdl,
	      const struct req_op_context *op_ctx, fsal_openflags_t openflags,
	      int *file_desc, struct attrlist *fsal_attr, bool reopen)
{
	fsal_status_t status = {ERR_FSAL_NO_ERROR, 0};
	struct gpfs_fsal_obj_handle *myself = NULL;
	struct gpfs_filesystem *gpfs_fs = NULL;
	int posix_flags = 0;
	int rc = 0;

	/* sanity checks. */
	if (!obj_hdl || !file_desc)
		return fsalstat(ERR_FSAL_FAULT, 0);

	myself = container_of(obj_hdl, struct gpfs_fsal_obj_handle, obj_handle);
	gpfs_fs = obj_hdl->fs->private;

	rc = fsal2posix_openflags(openflags, &posix_flags);
	if (rc) {  /* flags conflicts. */
		LogWarn(COMPONENT_FSAL, "Invalid/conflicting flags : %#X",
			openflags);
		return fsalstat(rc, 0);
	}

	status = fsal_internal_handle2fd(gpfs_fs->root_fd, myself->handle,
					 file_desc, posix_flags, reopen);

	if (FSAL_IS_ERROR(status)) {
		/** In some environments, "root" is denied write access,
		 * so try with the request credentials if the above call
		 * fails.
		 */
		fsal_set_credentials(op_ctx->creds);
		status = fsal_internal_handle2fd(gpfs_fs->root_fd,
						 myself->handle,
						 file_desc, posix_flags,
						 reopen);
		fsal_restore_ganesha_credentials();
	}

	if (FSAL_IS_ERROR(status))
		return status;

	/* output attributes */
	if (fsal_attr) {
		fsal_attr->mask = GPFS_SUPPORTED_ATTRIBUTES;
		status = GPFSFSAL_getattrs(op_ctx->fsal_export, gpfs_fs,
					   op_ctx, myself->handle, fsal_attr);
		if (FSAL_IS_ERROR(status)) {
			close(*file_desc);
			return status;
		}
	}

	return status;
}

/** @fn fsal_status_t
 *	GPFSFSAL_read(int fd, uint64_t offset, size_t buffer_size, caddr_t buffer,
 *		      size_t *p_read_amount, bool *p_end_of_file)
 *  @brief Perform a read operation on an opened file.
 *  @param fd The file descriptor returned by FSAL_open.
 *  @offset Offset
 *  @param buf_size Amount (in bytes) of data to be read.
 *  @param buf Address where the read data is to be stored in memory.
 *  @param read_amount Pointer to the amount of data (in bytes) that have been read
 *        during this call.
 *  @param end_of_file Pointer to a boolean that indicates whether the end of file
 *        has been reached during this call.
 *
 *  @return ERR_FSAL_NO_ERROR on success, error otherwise.
 */
fsal_status_t
GPFSFSAL_read(int fd, uint64_t offset, size_t buf_size, caddr_t buf,
	      size_t *read_amount, bool *end_of_file)
{
	struct read_arg rarg = {0};
	ssize_t nb_read = 0;
	int errsv = 0;

	/* sanity checks. */
	if (!buf || !read_amount || !end_of_file)
		return fsalstat(ERR_FSAL_FAULT, 0);

	rarg.mountdirfd = fd;
	rarg.fd = fd;
	rarg.bufP = buf;
	rarg.offset = offset;
	rarg.length = buf_size;
	rarg.options = 0;

	fsal_set_credentials(op_ctx->creds);
	nb_read = gpfs_ganesha(OPENHANDLE_READ_BY_FD, &rarg);
	errsv = errno;
	fsal_restore_ganesha_credentials();

	if (nb_read == -1) {
		if (errsv == EUNATCH)
			LogFatal(COMPONENT_FSAL, "GPFS Returned EUNATCH");
		return fsalstat(posix2fsal_error(errsv), errsv);
	}

	if (nb_read == 0 || nb_read < buf_size)
		*end_of_file = true;

	*read_amount = nb_read;

	return fsalstat(ERR_FSAL_NO_ERROR, 0);
}

/** @fn fsal_status_t
 *	GPFSFSAL_write(int fd, uint64_t offset, size_t buf_size, caddr_t buf,
 *		       size_t *write_amount, bool *fsal_stable,
 *		       const struct req_op_context *op_ctx)
 *  @brief Perform a write operation on an opened file.
 *
 *  @param fd The file descriptor returned by FSAL_open.
 *  @param buf_size Amount (in bytes) of data to be written.
 *  @param buf Address where the data is in memory.
 *  @param write_amount Pointer to the amount of data (in bytes) that have been written
 *        during this call.
 *
 * @return ERR_FSAL_NO_ERROR on success, error otherwise
 */
fsal_status_t
GPFSFSAL_write(int fd, uint64_t offset, size_t buf_size, caddr_t buf,
	       size_t *write_amount, bool *fsal_stable,
	       const struct req_op_context *op_ctx)
{
	struct write_arg warg = {0};
	uint32_t stability_got = 0;
	ssize_t nb_write = 0;
	int errsv = 0;

	/* sanity checks. */
	if (!buf || !write_amount)
		return fsalstat(ERR_FSAL_FAULT, 0);

	warg.mountdirfd = fd;
	warg.fd = fd;
	warg.bufP = buf;
	warg.offset = offset;
	warg.length = buf_size;
	warg.stability_wanted = *fsal_stable;
	warg.stability_got = &stability_got;
	warg.options = 0;

	fsal_set_credentials(op_ctx->creds);
	nb_write = gpfs_ganesha(OPENHANDLE_WRITE_BY_FD, &warg);
	errsv = errno;
	fsal_restore_ganesha_credentials();

	if (nb_write == -1) {
		if (errsv == EUNATCH)
			LogFatal(COMPONENT_FSAL, "GPFS Returned EUNATCH");
		return fsalstat(posix2fsal_error(errsv), errsv);
	}

	*write_amount = nb_write;
	*fsal_stable = (stability_got) ? true : false;

	return fsalstat(ERR_FSAL_NO_ERROR, 0);
}

/** @fn fsal_status_t
 *	GPFSFSAL_alloc(int fd, uint64_t offset, uint64_t length, bool allocate)
 *  @brief Perform a de/allocc operation on an opened file.
 *  @param fd The file descriptor returned by FSAL_open.
 *  @param offset Offset
 *  @param length Length
 *  @param allocate Allocate
 *
 *  @return ERR_FSAL_NO_ERROR on success, error otherwise
 */
fsal_status_t
GPFSFSAL_alloc(int fd, uint64_t offset, uint64_t length, bool allocate)
{
	struct alloc_arg aarg = {0};
	int errsv = 0;
	int rc = 0;

	aarg.fd = fd;
	aarg.offset = offset;
	aarg.length = length;
	aarg.options = (allocate) ? IO_ALLOCATE : IO_DEALLOCATE;

	fsal_set_credentials(op_ctx->creds);
	rc = gpfs_ganesha(OPENHANDLE_ALLOCATE_BY_FD, &aarg);
	errsv = errno;
	fsal_restore_ganesha_credentials();

	if (rc == -1) {
		if (errsv == EUNATCH)
			LogFatal(COMPONENT_FSAL, "GPFS Returned EUNATCH");
		return fsalstat(posix2fsal_error(errsv), errsv);
	}
	return fsalstat(ERR_FSAL_NO_ERROR, 0);
}
