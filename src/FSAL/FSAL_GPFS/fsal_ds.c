/*
 * Copyright © 2012 CohortFS, LLC.
 * Author: Adam C. Emerson <aemerson@linuxbox.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * as published by the Free Software Foundation; either version 3 of
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301 USA
 *
 * -------------
 */

/**
 * @file   fsal_ds.c
 * @author Adam C. Emerson <aemerson@linuxbox.com>
 * @date   Mon Jul 30 12:29:22 2012
 *
 * @brief pNFS DS operations for GPFS
 *
 * This file implements the read, write, commit, and dispose
 * operations for GPFS data-server handles.
 *
 * Also, creating a data server handle -- now called via the DS itself.
 */

#include <fcntl.h>
#include "fsal_api.h"
#include "FSAL/fsal_commonlib.h"
#include "../fsal_private.h"
#include "fsal_convert.h"
#include "fsal_internal.h"
#include "gpfs_methods.h"
#include "pnfs_utils.h"
#include "nfs_creds.h"

/** @fn static void ds_release(struct fsal_ds_handle *const ds_pub)
 *  @brief Release a DS handle
 *
 *  @param[in] ds_pub The object to release
 */
static void ds_release(struct fsal_ds_handle *const ds_pub)
{
	/* The private 'full' DS handle */
	struct gpfs_ds *ds = container_of(ds_pub, struct gpfs_ds, ds);

	fsal_ds_handle_fini(&ds->ds);
	gsh_free(ds);
}

/** @fn static nfsstat4
 *	ds_read(struct fsal_ds_handle *const ds_pub,
 *		struct req_op_context *const op_ctx, const stateid4 *stateid,
 *		const offset4 offset, const count4 req_len, void *const buffer,
 *		count4 *const sup_len, bool *const end_of_file)
 *
 *  @brief Read from a data-server handle.
 *
 *  NFSv4.1 data server handles are disjount from normal
 *  filehandles (in Ganesha, there is a ds_flag in the filehandle_v4_t
 *  structure) and do not get loaded into cache_inode or processed the
 *  normal way.
 *
 *  @param[in]  ds_pub    FSAL DS handle
 *  @param[in]  op_ctx    Credentials
 *  @param[in]  stateid   The stateid supplied with the READ operation,
 *                        for validation
 *  @param[in]  offset    The offset at which to read
 *  @param[in]  req_len   Length of read requested (and size of buffer)
 *  @param[out] buffer    The buffer to which to store read data
 *  @param[out] sup_len   Length of data read
 *  @param[out] eof       True on end of file
 *
 *  @return An NFSv4.1 status code.
 */
static nfsstat4
ds_read(struct fsal_ds_handle *const ds_pub,
	struct req_op_context *const op_ctx, const stateid4 *stateid,
	const offset4 offset, const count4 req_len, void *const buffer,
	count4 *const sup_len, bool *const end_of_file)
{
	/* The private 'full' DS handle */
	struct gpfs_ds *ds = container_of(ds_pub, struct gpfs_ds, ds);
	struct gpfs_file_handle *gpfs_fh = &ds->wire;
	struct dsread_arg rarg = {0};
	unsigned int *fh = (int *)&(gpfs_fh->f_handle);
	int amount_read = 0;  /** The amount actually read */
	int errsv = 0;

	rarg.mountdirfd = ds->gpfs_fs->root_fd;
	rarg.handle = gpfs_fh;
	rarg.bufP = buffer;
	rarg.offset = offset;
	rarg.length = req_len;
	rarg.options = 0;

	LogDebug(COMPONENT_PNFS,
		 "fh len %d type %d key %d: %08x %08x %08x %08x %08x %08x %08x %08x %08x %08x\n",
		 gpfs_fh->handle_size, gpfs_fh->handle_type,
		 gpfs_fh->handle_key_size, fh[0], fh[1], fh[2], fh[3],
		 fh[4], fh[5], fh[6], fh[7], fh[8], fh[9]);

	amount_read = gpfs_ganesha(OPENHANDLE_DS_READ, &rarg);
	errsv = errno;
	if (amount_read < 0) {
		if (errsv == EUNATCH)
			LogFatal(COMPONENT_PNFS, "GPFS Returned EUNATCH");
		return posix2nfs4_error(errsv);
	}

	*sup_len = amount_read;

	if (amount_read == 0 || amount_read < req_len)
		*end_of_file = true;

	return NFS4_OK;
}

/** @fn static nfsstat4
 *	ds_read_plus(struct fsal_ds_handle *const ds_pub,
 *		     struct req_op_context *const op_ctx,
 *		     const stateid4 *stateid, const offset4 offset,
 *		     const count4 requested_length, void *const buffer,
 *		     const count4 supplied_length, bool * const end_of_file,
 *		     struct io_info *info)
 *  @brief Read plus from a data-server handle.
 *
 *  NFSv4.2 data server handles are disjount from normal
 *  filehandles (in Ganesha, there is a ds_flag in the filehandle_v4_t
 *  structure) and do not get loaded into cache_inode or processed the
 *  normal way.
 *
 *  @param[in]  ds_pub           FSAL DS handle
 *  @param[in]  op_ctx           Credentials
 *  @param[in]  stateid          The stateid supplied with the READ operation,
 *                               for validation
 *  @param[in]  offset           The offset at which to read
 *  @param[in]  requested_length Length of read requested (and size of buffer)
 *  @param[out] buffer           The buffer to which to store read data
 *  @param[out] supplied_length  Length of data read
 *  @param[out] eof              True on end of file
 *  @param[out] info             IO info
 *
 *  @return An NFSv4.2 status code.
 */
static nfsstat4
ds_read_plus(struct fsal_ds_handle *const ds_pub,
	     struct req_op_context *const op_ctx,
	     const stateid4 *stateid, const offset4 offset,
	     const count4 req_len, void *const buffer,
	     const count4 sup_len, bool * const end_of_file,
	     struct io_info *info)
{
	/* The private 'full' DS handle */
	struct gpfs_ds *ds = container_of(ds_pub, struct gpfs_ds, ds);
	struct gpfs_file_handle *gpfs_fh = &ds->wire;
	struct dsread_arg rarg = {0};
	unsigned int *fh = (int *)&(gpfs_fh->f_handle);
	int amount_read = 0;	/* The amount actually read */
	uint64_t filesize;
	int errsv = 0;

	rarg.mountdirfd = ds->gpfs_fs->root_fd;
	rarg.handle = gpfs_fh;
	rarg.bufP = buffer;
	rarg.offset = offset;
	rarg.length = req_len;
	rarg.filesize = &filesize;
	rarg.options = IO_SKIP_HOLE;

	LogDebug(COMPONENT_PNFS,
		 "fh len %d type %d key %d: %08x %08x %08x %08x %08x %08x %08x %08x %08x %08x\n",
		 gpfs_fh->handle_size, gpfs_fh->handle_type,
		 gpfs_fh->handle_key_size, fh[0], fh[1], fh[2], fh[3],
		 fh[4], fh[5], fh[6], fh[7], fh[8], fh[9]);

	amount_read = gpfs_ganesha(OPENHANDLE_DS_READ, &rarg);
	errsv = errno;
	if (amount_read >= 0) {
		info->io_content.what = NFS4_CONTENT_DATA;
		info->io_content.data.d_offset = offset + amount_read;
		info->io_content.data.d_data.data_len = amount_read;
		info->io_content.data.d_data.data_val = buffer;
		if (amount_read == 0 || amount_read < req_len)
			*end_of_file = true;

		return NFS4_OK;
	}

	/** error while reading */

	if (errsv == EUNATCH)
		LogFatal(COMPONENT_PNFS, "GPFS Returned EUNATCH");
	if (errsv != ENODATA)
		return posix2nfs4_error(errsv);

	/* errsv == ENODATA */
	info->io_content.what = NFS4_CONTENT_HOLE;
	info->io_content.hole.di_offset = offset;   /*offset of hole*/

	if ((req_len + offset) > filesize) {
		amount_read = filesize - offset;
		if (amount_read < 0) {
			amount_read = 0;
			*end_of_file = true;
		} else if (amount_read < req_len)
			*end_of_file = true;
		info->io_content.hole.di_length = amount_read;
	} else
		info->io_content.hole.di_length = req_len;  /*hole len*/

	return NFS4_OK;
}

/** @fn static nfsstat4
 *	ds_write(struct fsal_ds_handle *const ds_pub,
 *		 struct req_op_context *const op_ctx, const stateid4 *stateid,
 *		 const offset4 offset, const count4 write_len,
 *		 const void *buffer, const stable_how4 stability_wanted,
 *		 count4 * const written_len, verifier4 * const writeverf,
 *		 stable_how4 * const stability_got)
 *
 *  @brief Write to a data-server handle.
 *
 *  This performs a DS write not going through the data server unless
 *  FILE_SYNC4 is specified, in which case it connects the filehandle
 *  and performs an MDS write.
 *
 *  @param[in]  ds_pub           FSAL DS handle
 *  @param[in]  op_ctx           Credentials
 *  @param[in]  stateid          The stateid supplied with the READ operation,
 *                               for validation
 *  @param[in]  offset           The offset at which to read
 *  @param[in]  write_len        Length of write requested (and size of buffer)
 *  @param[out] buffer           The buffer to which to store read data
 *  @param[in]  stability wanted Stability of write
 *  @param[out] written_len      Length of data written
 *  @param[out] writeverf        Write verifier
 *  @param[out] stability_got    Stability used for write (must be as
 *                               or more stable than request)
 *
 *  @return An NFSv4.1 status code.
 */
static nfsstat4
ds_write(struct fsal_ds_handle *const ds_pub,
	 struct req_op_context *const op_ctx, const stateid4 *stateid,
	 const offset4 offset, const count4 write_len, const void *buffer,
	 const stable_how4 stability_wanted, count4 * const written_len,
	 verifier4 * const writeverf, stable_how4 * const stability_got)
{
	/* The private 'full' DS handle */
	struct gpfs_ds *ds = container_of(ds_pub, struct gpfs_ds, ds);
	struct gpfs_file_handle *gpfs_fh = &ds->wire;
	unsigned int *fh = (int *)&(gpfs_fh->f_handle);
	struct dswrite_arg warg = {0};
	struct gsh_buffdesc key = {0};
	int32_t amount_written = 0;	/* The amount actually read */
	int errsv = 0;

	memset(writeverf, 0, NFS4_VERIFIER_SIZE);

	warg.mountdirfd = ds->gpfs_fs->root_fd;
	warg.handle = gpfs_fh;
	warg.bufP = (char *)buffer;
	warg.offset = offset;
	warg.length = write_len;
	warg.stability_wanted = stability_wanted;
	warg.stability_got = stability_got;
	warg.verifier4 = (uint32_t *) writeverf;
	warg.options = 0;

	LogDebug(COMPONENT_PNFS,
		 "fh len %d type %d key %d: %08x %08x %08x %08x %08x %08x %08x %08x %08x %08x\n",
		 gpfs_fh->handle_size, gpfs_fh->handle_type,
		 gpfs_fh->handle_key_size, fh[0], fh[1], fh[2], fh[3],
		 fh[4], fh[5], fh[6], fh[7], fh[8], fh[9]);

	amount_written = gpfs_ganesha(OPENHANDLE_DS_WRITE, &warg);
	errsv = errno;
	if (amount_written < 0) {
		if (errsv == EUNATCH)
			LogFatal(COMPONENT_PNFS, "GPFS Returned EUNATCH");
		return posix2nfs4_error(errsv);
	}

	LogDebug(COMPONENT_PNFS, "write verifier %d-%d\n", warg.verifier4[0],
		 warg.verifier4[1]);

	key.addr = gpfs_fh;
	key.len = gpfs_fh->handle_key_size;
	fsal_invalidate(op_ctx->fsal_export->fsal, &key,
			CACHE_INODE_INVALIDATE_ATTRS |
			CACHE_INODE_INVALIDATE_CONTENT);

	set_gpfs_verifier(writeverf);

	*written_len = amount_written;

	return NFS4_OK;
}

/** @fn static nfsstat4
 *	ds_write_plus(struct fsal_ds_handle *const ds_pub,
 *		      struct req_op_context *const op_ctx,
 *		      const stateid4 *stateid, const offset4 offset,
 *		      const count4 write_len, const void *buffer,
 *		      const stable_how4 stability_wanted,
 *		      count4 * const written_len, verifier4 * const writeverf,
 *		      stable_how4 * const stability_got, struct io_info *info)
 *
 *  @brief Write plus to a data-server handle.
 *
 *  This performs a DS write not going through the data server unless
 *  FILE_SYNC4 is specified, in which case it connects the filehandle
 *  and performs an MDS write.
 *
 *  @param[in]  ds_pub           FSAL DS handle
 *  @param[in]  op_ctx           Credentials
 *  @param[in]  stateid          The stateid supplied with the READ operation,
 *                               for validation
 *  @param[in]  offset           The offset at which to read
 *  @param[in]  write_len        Length of write requested (and size of buffer)
 *  @param[out] buffer           The buffer to which to store read data
 *  @param[in]  stability wanted Stability of write
 *  @param[out] written_len      Length of data written
 *  @param[out] writeverf        Write verifier
 *  @param[out] stability_got    Stability used for write (must be as
 *                               or more stable than request)
 *  @param[in/out] info          IO info
 *
 *  @return An NFSv4.2 status code.
 */
static nfsstat4
ds_write_plus(struct fsal_ds_handle *const ds_pub,
	      struct req_op_context *const op_ctx, const stateid4 *stateid,
	      const offset4 offset, const count4 write_len, const void *buffer,
	      const stable_how4 stability_wanted, count4 * const written_len,
	      verifier4 * const writeverf, stable_how4 * const stability_got,
	      struct io_info *info)
{
	/* The private 'full' DS handle */
	struct gpfs_ds *ds = container_of(ds_pub, struct gpfs_ds, ds);
	struct gpfs_file_handle *gpfs_fh = &ds->wire;
	unsigned int *fh = (int *)&(gpfs_fh->f_handle);
	struct dswrite_arg warg = {0};
	struct gsh_buffdesc key = {0};
	int32_t amount_written = 0;	/* The amount actually read */
	int errsv = 0;

	memset(writeverf, 0, NFS4_VERIFIER_SIZE);

	warg.mountdirfd = ds->gpfs_fs->root_fd;
	warg.handle = gpfs_fh;
	warg.bufP = (char *)buffer;
	warg.offset = offset;
	warg.length = write_len;
	warg.stability_wanted = stability_wanted;
	warg.stability_got = stability_got;
	warg.verifier4 = (uint32_t *) writeverf;
	warg.options = 0;

	if (info->io_content.what == NFS4_CONTENT_HOLE)
		warg.options = IO_SKIP_HOLE;

	LogDebug(COMPONENT_PNFS,
		 "fh len %d type %d key %d: %08x %08x %08x %08x %08x %08x %08x %08x %08x %08x\n",
		 gpfs_fh->handle_size, gpfs_fh->handle_type,
		 gpfs_fh->handle_key_size, fh[0], fh[1], fh[2], fh[3],
		 fh[4], fh[5], fh[6], fh[7], fh[8], fh[9]);

	amount_written = gpfs_ganesha(OPENHANDLE_DS_WRITE, &warg);
	errsv = errno;
	if (amount_written < 0) {
		if (errsv == EUNATCH)
			LogFatal(COMPONENT_PNFS, "GPFS Returned EUNATCH");
		return posix2nfs4_error(errsv);
	}

	LogDebug(COMPONENT_PNFS, "write verifier %d-%d\n",
				warg.verifier4[0], warg.verifier4[1]);

	key.addr = gpfs_fh;
	key.len = gpfs_fh->handle_key_size;
	fsal_invalidate(op_ctx->fsal_export->fsal, &key,
			CACHE_INODE_INVALIDATE_ATTRS |
			CACHE_INODE_INVALIDATE_CONTENT);

	set_gpfs_verifier(writeverf);

	*written_len = amount_written;

	return NFS4_OK;
}

/** @fn static nfsstat4
 *	ds_commit(struct fsal_ds_handle *const ds_pub,
 *		  struct req_op_context *const op_ctx, const offset4 offset,
 *		  const count4 count, verifier4 * const writeverf)
 *  @brief Commit a byte range to a DS handle.
 *
 *  NFSv4.1 data server filehandles are disjount from normal
 *  filehandles (in Ganesha, there is a ds_flag in the filehandle_v4_t
 *  structure) and do not get loaded into cache_inode or processed the
 *  normal way.
 *
 *  @param[in]  ds_pub    FSAL DS handle
 *  @param[in]  op_ctx    Credentials
 *  @param[in]  offset    Start of commit window
 *  @param[in]  count     Length of commit window
 *  @param[out] writeverf Write verifier
 *
 *  @return An NFSv4.1 status code.
 */
static nfsstat4
ds_commit(struct fsal_ds_handle *const ds_pub,
	  struct req_op_context *const op_ctx, const offset4 offset,
	  const count4 count, verifier4 * const writeverf)
{
	memset(writeverf, 0, NFS4_VERIFIER_SIZE);

	LogCrit(COMPONENT_PNFS, "Commits should go to MDS\n");
	/* GPFS asked for COMMIT to go to the MDS */
	return NFS4ERR_INVAL;
}

/** @fn static void dsh_ops_init(struct fsal_dsh_ops *ops)
 */
static void dsh_ops_init(struct fsal_dsh_ops *ops)
{
	/* redundant copy, but you never know about the future... */
	memcpy(ops, &def_dsh_ops, sizeof(struct fsal_dsh_ops));

	ops->release = ds_release;
	ops->read = ds_read;
	ops->read_plus = ds_read_plus;
	ops->write = ds_write;
	ops->write_plus = ds_write_plus;
	ops->commit = ds_commit;
}

/** @fn static nfsstat4
 *	make_ds_handle(struct fsal_pnfs_ds *const pds,
 *		       const struct gsh_buffdesc *const desc,
 *		       struct fsal_ds_handle **const handle, int flags)
 *  @brief Try to create a FSAL data server handle from a wire handle
 *
 *  This function creates a FSAL data server handle from a client
 *  supplied "wire" handle.  This is also where validation gets done,
 *  since PUTFH is the only operation that can return
 *  NFS4ERR_BADHANDLE.
 *
 *  @param[in]  pds      FSAL pNFS DS
 *  @param[in]  desc     Buffer from which to create the file
 *  @param[out] handle   FSAL DS handle
 *
 *  @return NFSv4.1 error codes.
 */
static nfsstat4
make_ds_handle(struct fsal_pnfs_ds *const pds,
	       const struct gsh_buffdesc *const desc,
	       struct fsal_ds_handle **const handle, int flags)
{
	struct gpfs_file_handle *fh = (struct gpfs_file_handle *)desc->addr;
	struct gpfs_ds *ds = NULL;		/* Handle to be created */
	struct fsal_filesystem *fs = NULL;
	struct fsal_fsid__ fsid = {0};

	*handle = NULL;

	if (desc->len != sizeof(struct gpfs_file_handle))
		return NFS4ERR_BADHANDLE;

	if (flags & FH_FSAL_BIG_ENDIAN) {
#if (BYTE_ORDER != BIG_ENDIAN)
		fh->handle_size = bswap_16(fh->handle_size);
		fh->handle_type = bswap_16(fh->handle_type);
		fh->handle_version = bswap_16(fh->handle_version);
		fh->handle_key_size = bswap_16(fh->handle_key_size);
#endif
	} else {
#if (BYTE_ORDER == BIG_ENDIAN)
		fh->handle_size = bswap_16(fh->handle_size);
		fh->handle_type = bswap_16(fh->handle_type);
		fh->handle_version = bswap_16(fh->handle_version);
		fh->handle_key_size = bswap_16(fh->handle_key_size);
#endif
	}
	LogFullDebug(COMPONENT_FSAL,
		     "flags 0x%X size %d type %d ver %d key_size %d FSID 0x%X:%X",
		     flags, fh->handle_size, fh->handle_type,
		     fh->handle_version, fh->handle_key_size,
		     fh->handle_fsid[0], fh->handle_fsid[1]);

	gpfs_extract_fsid(fh, &fsid);

	fs = lookup_fsid(&fsid, GPFS_FSID_TYPE);
	if (fs == NULL) {
		LogInfo(COMPONENT_FSAL,
			"Could not find filesystem for fsid=0x%016"PRIx64
			".0x%016"PRIx64" from handle", fsid.major, fsid.minor);
		return NFS4ERR_STALE;
	}

	if (fs->fsal != pds->fsal) {
		LogInfo(COMPONENT_FSAL,
			"Non GPFS filesystem fsid=0x%016"PRIx64".0x%016"PRIx64
			" from handle", fsid.major, fsid.minor);
		return NFS4ERR_STALE;
	}

	ds = gsh_calloc(sizeof(struct gpfs_ds), 1);
	if (ds == NULL)
		return NFS4ERR_SERVERFAULT;

	*handle = &ds->ds;
	fsal_ds_handle_init(*handle, pds);

	/** Connect lazily when a FILE_SYNC4 write forces us to, not here. */

	ds->connected = false;

	ds->gpfs_fs = fs->private;

	memcpy(&ds->wire, desc->addr, desc->len);

	return NFS4_OK;
}

/** @fn static nfsstat4
 *	pds_permissions(struct fsal_pnfs_ds *const pds, struct svc_req *req)
 */
static nfsstat4
pds_permissions(struct fsal_pnfs_ds *const pds, struct svc_req *req)
{
	/* special case: related export has been set */
	return nfs4_export_check_access(req);
}

/** @fn void pnfs_ds_ops_init(struct fsal_pnfs_ds_ops *ops)
 *  @param ops FSAL pNFS ds ops
 */
void pnfs_ds_ops_init(struct fsal_pnfs_ds_ops *ops)
{
	memcpy(ops, &def_pnfs_ds_ops, sizeof(struct fsal_pnfs_ds_ops));
	ops->permissions = pds_permissions;
	ops->make_ds_handle = make_ds_handle;
	ops->fsal_dsh_ops = dsh_ops_init;
}
