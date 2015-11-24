/** @file export.c
 *  @brief GPFS FSAL module export functions.
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

#include <fcntl.h>
#include <libgen.h>		/* used for 'dirname' */
#include <pthread.h>
#include <string.h>
#include <sys/types.h>
#include <mntent.h>
#include <sys/statfs.h>
#include <sys/quota.h>
#include <sys/types.h>
#include "fsal.h"
#include "fsal_internal.h"
#include "fsal_convert.h"
#include "FSAL/fsal_commonlib.h"
#include "FSAL/fsal_config.h"
#include "gpfs_methods.h"
#include "nfs_exports.h"
#include "export_mgr.h"
#include "pnfs_utils.h"

/** @fn static void release(struct fsal_export *exp_hdl)
 */
static void release(struct fsal_export *exp_hdl)
{
	struct gpfs_fsal_export *myself =
	    container_of(exp_hdl, struct gpfs_fsal_export, export);

	gpfs_unexport_filesystems(myself);
	fsal_detach_export(exp_hdl->fsal, &exp_hdl->exports);
	free_export_ops(exp_hdl);

	gsh_free(myself);
}

/** @fn static fsal_status_t get_dynamic_info(struct fsal_export *exp_hdl,
 *				      struct fsal_obj_handle *obj_hdl,
 *				      fsal_dynamicfsinfo_t *infop)
 */
static fsal_status_t
get_dynamic_info(struct fsal_export *exp_hdl, struct fsal_obj_handle *obj_hdl,
		 fsal_dynamicfsinfo_t *infop)
{
	struct statfs buff = {0};
	struct gpfs_filesystem *gpfs_fs = NULL;
	fsal_status_t status = {ERR_FSAL_NO_ERROR, 0};

	if ((infop == NULL) ||
	    (obj_hdl == NULL) || (obj_hdl->fs == NULL) ||
	    (obj_hdl->fs->private == NULL))
		return fsalstat(ERR_FSAL_FAULT, 0);

	gpfs_fs = obj_hdl->fs->private;
	status = GPFSFSAL_statfs(gpfs_fs->root_fd, obj_hdl, &buff);
	if (FSAL_IS_ERROR(status))
		return status;

	infop->total_bytes = buff.f_frsize * buff.f_blocks;
	infop->free_bytes = buff.f_frsize * buff.f_bfree;
	infop->avail_bytes = buff.f_frsize * buff.f_bavail;
	infop->total_files = buff.f_files;
	infop->free_files = buff.f_ffree;
	infop->avail_files = buff.f_ffree;
	infop->time_delta.tv_sec = 1;
	infop->time_delta.tv_nsec = 0;

	return fsalstat(ERR_FSAL_NO_ERROR, 0);
}

/** @fn static bool fs_supports(struct fsal_export *exp_hdl,
 *			fsal_fsinfo_options_t option)
 */
static bool fs_supports(struct fsal_export *exp_hdl,
			fsal_fsinfo_options_t option)
{
	return fsal_supports(gpfs_staticinfo(exp_hdl->fsal), option);
}

/** @fn static uint64_t fs_maxfilesize(struct fsal_export *exp_hdl)
 */
static uint64_t fs_maxfilesize(struct fsal_export *exp_hdl)
{
	return fsal_maxfilesize(gpfs_staticinfo(exp_hdl->fsal));
}

/** @fn static uint32_t fs_maxread(struct fsal_export *exp_hdl)
 */
static uint32_t fs_maxread(struct fsal_export *exp_hdl)
{
	return fsal_maxread(gpfs_staticinfo(exp_hdl->fsal));
}

/** @fn static uint32_t fs_maxwrite(struct fsal_export *exp_hdl)
 */
static uint32_t fs_maxwrite(struct fsal_export *exp_hdl)
{
	return fsal_maxwrite(gpfs_staticinfo(exp_hdl->fsal));
}

/** @fn static uint32_t fs_maxlink(struct fsal_export *exp_hdl)
 */
static uint32_t fs_maxlink(struct fsal_export *exp_hdl)
{
	return fsal_maxlink(gpfs_staticinfo(exp_hdl->fsal));
}

/** @fn static uint32_t fs_maxnamelen(struct fsal_export *exp_hdl)
 */
static uint32_t fs_maxnamelen(struct fsal_export *exp_hdl)
{
	return fsal_maxnamelen(gpfs_staticinfo(exp_hdl->fsal));
}

/** @fn static uint32_t fs_maxpathlen(struct fsal_export *exp_hdl)
 */
static uint32_t fs_maxpathlen(struct fsal_export *exp_hdl)
{
	return fsal_maxpathlen(gpfs_staticinfo(exp_hdl->fsal));
}

/** @fn static struct timespec fs_lease_time(struct fsal_export *exp_hdl)
 */
static struct timespec fs_lease_time(struct fsal_export *exp_hdl)
{
	return fsal_lease_time(gpfs_staticinfo(exp_hdl->fsal));
}

/** @fn static fsal_aclsupp_t fs_acl_support(struct fsal_export *exp_hdl)
 */
static fsal_aclsupp_t fs_acl_support(struct fsal_export *exp_hdl)
{
	return fsal_acl_support(gpfs_staticinfo(exp_hdl->fsal));
}

/** @fn static attrmask_t fs_supported_attrs(struct fsal_export *exp_hdl)
 */
static attrmask_t fs_supported_attrs(struct fsal_export *exp_hdl)
{
	return fsal_supported_attrs(gpfs_staticinfo(exp_hdl->fsal));
}

/** @fn static uint32_t fs_umask(struct fsal_export *exp_hdl)
 */
static uint32_t fs_umask(struct fsal_export *exp_hdl)
{
	return fsal_umask(gpfs_staticinfo(exp_hdl->fsal));
}

/** @fn static uint32_t fs_xattr_access_rights(struct fsal_export *exp_hdl)
 */
static uint32_t fs_xattr_access_rights(struct fsal_export *exp_hdl)
{
	return fsal_xattr_access_rights(gpfs_staticinfo(exp_hdl->fsal));
}

/** @fn static fsal_status_t
 *       get_quota(struct fsal_export *exp_hdl, const char *filepath, int quota_type,
 *	 fsal_quota_t *pquota)
 *  @brief return quotas for this export.
 *
 *  path could cross a lower mount boundary which could
 *  mask lower mount values with those of the export root
 *  if this is a real issue, we can scan each time with setmntent()
 *  better yet, compare st_dev of the file with st_dev of root_fd.
 *  on linux, can map st_dev -> /proc/partitions name -> /dev/<name>
 *
 *  @return FSAL status
 */
static fsal_status_t
get_quota(struct fsal_export *exp_hdl, const char *filepath, int quota_type,
	  fsal_quota_t *pquota)
{
	struct gpfs_fsal_export *myself =
		container_of(exp_hdl, struct gpfs_fsal_export, export);
	struct dqblk fs_quota = {0};
	struct stat path_stat = {0};
	fsal_errors_t fsal_error = ERR_FSAL_NO_ERROR;
	uid_t id = ANON_UID;
	int retval = 0;

	if (stat(filepath, &path_stat) != 0) {
		retval = errno;
		LogMajor(COMPONENT_FSAL,
			 "GPFS get_quota, fstat: root_path: %s, errno=(%d) %s",
			 myself->root_fs->path, retval, strerror(retval));
		fsal_error = posix2fsal_error(retval);
		goto out;
	}

	if ((major(path_stat.st_dev) != myself->root_fs->dev.major) ||
	    (minor(path_stat.st_dev) != myself->root_fs->dev.minor)) {
		LogMajor(COMPONENT_FSAL,
			 "GPFS get_quota: crossed mount boundary! root_path: %s, quota path: %s",
			 myself->root_fs->path, filepath);
		fsal_error = ERR_FSAL_FAULT;	/* maybe a better error? */
		goto out;
	}

	id = (quota_type == USRQUOTA) ? op_ctx->creds->caller_uid :
					op_ctx->creds->caller_gid;

	if (quotactl(QCMD(Q_GETQUOTA, quota_type), myself->root_fs->device,
		     id, (caddr_t) &fs_quota) != 0) {
		retval = errno;
		fsal_error = posix2fsal_error(retval);
		goto out;
	}

	pquota->bhardlimit = fs_quota.dqb_bhardlimit;
	pquota->bsoftlimit = fs_quota.dqb_bsoftlimit;
	pquota->curblocks = fs_quota.dqb_curspace;
	pquota->fhardlimit = fs_quota.dqb_ihardlimit;
	pquota->fsoftlimit = fs_quota.dqb_isoftlimit;
	pquota->curfiles = fs_quota.dqb_curinodes;
	pquota->btimeleft = fs_quota.dqb_btime;
	pquota->ftimeleft = fs_quota.dqb_itime;
	pquota->bsize = DEV_BSIZE;

 out:
	return fsalstat(fsal_error, retval);
}

/** @fn static fsal_status_t
 *      set_quota(struct fsal_export *exp_hdl, const char *filepath, int quota_type,
 *	fsal_quota_t *pquota, fsal_quota_t *presquota)
 *  @brief same lower mount restriction applies
 *  @return FSAL status
 */
static fsal_status_t
set_quota(struct fsal_export *exp_hdl, const char *filepath, int quota_type,
	  fsal_quota_t *pquota, fsal_quota_t *presquota)
{
	struct gpfs_fsal_export *myself =
		container_of(exp_hdl, struct gpfs_fsal_export, export);
	struct dqblk fs_quota = {0};
	struct stat path_stat = {0};
	fsal_errors_t fsal_error = ERR_FSAL_NO_ERROR;
	uid_t id = ANON_UID;
	int retval = 0;

	if (stat(filepath, &path_stat) != 0) {
		retval = errno;
		LogMajor(COMPONENT_FSAL,
			 "GPFS set_quota, fstat: root_path: %s, errno=(%d) %s",
			 myself->root_fs->path, retval, strerror(retval));
		fsal_error = posix2fsal_error(retval);
		goto out;
	}

	if ((major(path_stat.st_dev) != myself->root_fs->dev.major) ||
	    (minor(path_stat.st_dev) != myself->root_fs->dev.minor)) {
		LogMajor(COMPONENT_FSAL,
			 "GPFS set_quota: crossed mount boundary! root_path: %s, quota path: %s",
			 myself->root_fs->path, filepath);
		fsal_error = ERR_FSAL_FAULT;	/* maybe a better error? */
		goto out;
	}

	id = (quota_type == USRQUOTA) ? op_ctx->creds->caller_uid :
					op_ctx->creds->caller_gid;

	if (pquota->bhardlimit != 0) {
		fs_quota.dqb_bhardlimit = pquota->bhardlimit;
		fs_quota.dqb_valid |= QIF_BLIMITS;
	}
	if (pquota->bsoftlimit != 0) {
		fs_quota.dqb_bsoftlimit = pquota->bsoftlimit;
		fs_quota.dqb_valid |= QIF_BLIMITS;
	}
	if (pquota->fhardlimit != 0) {
		fs_quota.dqb_ihardlimit = pquota->fhardlimit;
		fs_quota.dqb_valid |= QIF_ILIMITS;
	}
	if (pquota->fsoftlimit != 0) {
		fs_quota.dqb_isoftlimit = pquota->fsoftlimit;
		fs_quota.dqb_valid |= QIF_ILIMITS;
	}
	if (pquota->btimeleft != 0) {
		fs_quota.dqb_btime = pquota->btimeleft;
		fs_quota.dqb_valid |= QIF_BTIME;
	}
	if (pquota->ftimeleft != 0) {
		fs_quota.dqb_itime = pquota->ftimeleft;
		fs_quota.dqb_valid |= QIF_ITIME;
	}

	if (quotactl(QCMD(Q_SETQUOTA, quota_type), myself->root_fs->device,
		     id, (caddr_t) &fs_quota) != 0) {
		retval = errno;
		fsal_error = posix2fsal_error(retval);
		goto out;
	}

	if (presquota != NULL)
		return get_quota(exp_hdl, filepath, quota_type, presquota);

 out:
	return fsalstat(fsal_error, retval);
}

/** @fn static fsal_status_t
 *      gpfs_extract_handle(struct fsal_export *exp_hdl, fsal_digesttype_t in_type,
 *			    struct gsh_buffdesc *fh_desc, int flags)
 *
 *  @brief extract a file handle from a buffer.
 *
 *  do verification checks and flag any and all suspicious bits.
 *  Return an updated fh_desc into whatever was passed.  The most
 *  common behavior, done here is to just reset the length.  There
 *  is the option to also adjust the start pointer.
 *
 *  @return FSAL status
 */
static fsal_status_t
gpfs_extract_handle(struct fsal_export *exp_hdl, fsal_digesttype_t in_type,
		    struct gsh_buffdesc *fh_desc, int flags)
{
	struct gpfs_file_handle *hdl = NULL;
	size_t fh_size = 0;

	if (fh_desc == NULL || fh_desc->addr == NULL)
		return fsalstat(ERR_FSAL_FAULT, 0);

	hdl = (struct gpfs_file_handle *)fh_desc->addr;

	if (flags & FH_FSAL_BIG_ENDIAN) {
#if (BYTE_ORDER != BIG_ENDIAN)
		hdl->handle_size = bswap_16(hdl->handle_size);
		hdl->handle_type = bswap_16(hdl->handle_type);
		hdl->handle_version = bswap_16(hdl->handle_version);
		hdl->handle_key_size = bswap_16(hdl->handle_key_size);
#endif
	} else {
#if (BYTE_ORDER == BIG_ENDIAN)
		hdl->handle_size = bswap_16(hdl->handle_size);
		hdl->handle_type = bswap_16(hdl->handle_type);
		hdl->handle_version = bswap_16(hdl->handle_version);
		hdl->handle_key_size = bswap_16(hdl->handle_key_size);
#endif
	}
	LogFullDebug(COMPONENT_FSAL,
		     "flags 0x%X size %d type %d ver %d key_size %d FSID 0x%X:%X",
		     flags, hdl->handle_size, hdl->handle_type,
		     hdl->handle_version, hdl->handle_key_size,
		     hdl->handle_fsid[0], hdl->handle_fsid[1]);

	fh_size = gpfs_sizeof_handle(hdl);
	if (fh_desc->len != fh_size) {
		LogMajor(COMPONENT_FSAL,
			 "Size mismatch for handle.  should be %lu, got %lu",
			 fh_size, fh_desc->len);
		return fsalstat(ERR_FSAL_SERVERFAULT, 0);
	}

	fh_desc->len = hdl->handle_key_size;
	return fsalstat(ERR_FSAL_NO_ERROR, 0);
}

/** \var GPFS_write_verifier
 *  @brief NFS V4 write verifier
 */
verifier4 GPFS_write_verifier;

/** @fn static void gpfs_verifier(struct gsh_buffdesc *verf_desc)
 */
static void gpfs_verifier(struct gsh_buffdesc *verf_desc)
{
	memcpy(verf_desc->addr, &GPFS_write_verifier, MIN(verf_desc->len,
							  sizeof(verifier4)));
}

/** @fn void set_gpfs_verifier(verifier4 *verifier)
 *  @brief set the global GPFS_write_verfier according to \a verifier
 *  @param verfier verifier4 type
 */
void set_gpfs_verifier(verifier4 *verifier)
{
	memcpy(&GPFS_write_verifier, verifier, sizeof(verifier4));
}

/** @fn void gpfs_export_ops_init(struct export_ops *ops)
 *  @brief overwrite vector entries with the methods that we support
 *  @param ops tpye of struct export_ops
 */
void gpfs_export_ops_init(struct export_ops *ops)
{
	ops->release = release;
	ops->lookup_path = gpfs_lookup_path;
	ops->extract_handle = gpfs_extract_handle;
	ops->create_handle = gpfs_create_handle;
	ops->get_fs_dynamic_info = get_dynamic_info;
	ops->fs_supports = fs_supports;
	ops->fs_maxfilesize = fs_maxfilesize;
	ops->fs_maxread = fs_maxread;
	ops->fs_maxwrite = fs_maxwrite;
	ops->fs_maxlink = fs_maxlink;
	ops->fs_maxnamelen = fs_maxnamelen;
	ops->fs_maxpathlen = fs_maxpathlen;
	ops->fs_lease_time = fs_lease_time;
	ops->fs_acl_support = fs_acl_support;
	ops->fs_supported_attrs = fs_supported_attrs;
	ops->fs_umask = fs_umask;
	ops->fs_xattr_access_rights = fs_xattr_access_rights;
	ops->get_quota = get_quota;
	ops->set_quota = set_quota;
	ops->get_write_verifier = gpfs_verifier;
}

/** @fn void free_gpfs_filesystem(struct gpfs_filesystem *gpfs_fs)
 *  @brief close root fd and free filesystem
 *  @param gpfs_fs GPFS filesystem
 */
void free_gpfs_filesystem(struct gpfs_filesystem *gpfs_fs)
{
	if (gpfs_fs->root_fd >= 0)
		close(gpfs_fs->root_fd);
	gsh_free(gpfs_fs);
}

/** @fn void gpfs_extract_fsid(struct gpfs_file_handle *fh,
 *			       struct fsal_fsid__ *fsid)
 *  @brief Extract major from from fsid
 *  @param fh GPFS file handle
 *  @param fsid FSAL ID
 */
void gpfs_extract_fsid(struct gpfs_file_handle *fh, struct fsal_fsid__ *fsid)
{
	memcpy(&fsid->major, fh->handle_fsid, sizeof(fsid->major));
	fsid->minor = 0;
}

/** @fn int open_root_fd(struct gpfs_filesystem *gpfs_fs)
 *  @brief Open root fd
 *  @param gpfs_fs GPFS filesystem
 *  @return 0(zero) on success, otherwise error.
 */
int open_root_fd(struct gpfs_filesystem *gpfs_fs)
{
	struct fsal_fsid__ fsid = {0};
	fsal_status_t status = {0};
	struct gpfs_file_handle fh = {0};
	int retval = 0;

	gpfs_fs->root_fd = open(gpfs_fs->fs->path, O_RDONLY | O_DIRECTORY);

	if (gpfs_fs->root_fd < 0) {
		retval = errno;
		LogMajor(COMPONENT_FSAL,
			 "Could not open GPFS mount point %s: rc = %s (%d)",
			 gpfs_fs->fs->path, strerror(retval), retval);
		return retval;
	}

	status = fsal_internal_get_handle_at(gpfs_fs->root_fd,
					     gpfs_fs->fs->path, &fh);

	if (FSAL_IS_ERROR(status)) {
		retval = status.minor;
		LogMajor(COMPONENT_FSAL,
			 "Get root handle for %s failed with %s (%d)",
			 gpfs_fs->fs->path, strerror(retval), retval);
		goto errout;
	}

	gpfs_extract_fsid(&fh, &fsid);

	retval = re_index_fs_fsid(gpfs_fs->fs, GPFS_FSID_TYPE, &fsid);

	if (retval < 0) {
		LogCrit(COMPONENT_FSAL,
			"Could not re-index GPFS file system fsid for %s",
			gpfs_fs->fs->path);
		retval = -retval;
		goto errout;
	}

	return retval;

errout:

	close(gpfs_fs->root_fd);
	gpfs_fs->root_fd = -1;

	return retval;
}

/** @fn int gpfs_claim_filesystem(struct fsal_filesystem *fs,
 *				  struct fsal_export *exp)
 *  @brief Claim GPFS filesystem
 *  @param fs FSAL filesystem
 *  @param exp FSAL export
 *  @return 0(zero) on success, otherwise error.
 */
int gpfs_claim_filesystem(struct fsal_filesystem *fs, struct fsal_export *exp)
{
	struct gpfs_filesystem *gpfs_fs = NULL;
	struct gpfs_filesystem_export_map *map = NULL;
	struct gpfs_fsal_export *myself =
		container_of(exp, struct gpfs_fsal_export, export);
	pthread_attr_t attr_thr;
	int retval = 0;

	if (strcmp(fs->type, "gpfs") != 0) {
		LogInfo(COMPONENT_FSAL,
			"Attempt to claim non-GPFS filesystem %s", fs->path);
		return ENXIO;
	}

	map = gsh_calloc(sizeof(struct gpfs_filesystem_export_map), 1);

	if (map == NULL) {
		LogCrit(COMPONENT_FSAL,
			"Out of memory to claim file system %s", fs->path);
		return ENOMEM;
	}

	if (fs->fsal != NULL) {
		if (fs->private != NULL) {
			gpfs_fs = fs->private;
			goto already_claimed;
		}

		LogCrit(COMPONENT_FSAL,
			"fs %s appears already claimed but doesn't have private data",
			fs->path);
			retval = EINVAL;
			goto errout;
	}

	if (fs->private != NULL) {
		LogCrit(COMPONENT_FSAL,
			"fs %s was not claimed but had non-NULL private data",
			fs->path);
		goto errout;
	}

	gpfs_fs = gsh_calloc(sizeof(struct gpfs_filesystem), 1);

	if (gpfs_fs == NULL) {
		LogCrit(COMPONENT_FSAL,
			"Out of memory to claim file system %s", fs->path);
		retval = ENOMEM;
		goto errout;
	}

	glist_init(&gpfs_fs->exports);
	gpfs_fs->root_fd = -1;
	gpfs_fs->fs = fs;

	retval = open_root_fd(gpfs_fs);

	if (retval != 0) {
		if (retval == ENOTTY) {
			LogInfo(COMPONENT_FSAL,
				"file system %s is not exportable with %s",
				fs->path, exp->fsal->name);
			retval = ENXIO;
		}
		goto errout;
	}

	memset(&attr_thr, 0, sizeof(attr_thr));
	if (pthread_attr_init(&attr_thr) != 0)
		LogCrit(COMPONENT_THREAD, "can't init pthread's attributes");

	if (pthread_attr_setscope(&attr_thr, PTHREAD_SCOPE_SYSTEM) != 0)
		LogCrit(COMPONENT_THREAD, "can't set pthread's scope");

	if (pthread_attr_setdetachstate(&attr_thr,
					PTHREAD_CREATE_JOINABLE) != 0)
		LogCrit(COMPONENT_THREAD, "can't set pthread's join state");

	if (pthread_attr_setstacksize(&attr_thr, 2116488) != 0)
		LogCrit(COMPONENT_THREAD, "can't set pthread's stack size");

	gpfs_fs->up_ops = exp->up_ops;

	if (pthread_create(&gpfs_fs->up_thread, &attr_thr, GPFSFSAL_UP_Thread,
			   gpfs_fs) != 0) {
		retval = errno;
		LogCrit(COMPONENT_THREAD,
			"Could not create GPFSFSAL_UP_Thread, error = %d (%s)",
			retval, strerror(retval));
		goto errout;
	}

	fs->private = gpfs_fs;

already_claimed:

	/* Now map the file system and export */
	map->fs = gpfs_fs;
	map->exp = myself;
	glist_add_tail(&gpfs_fs->exports, &map->on_exports);
	glist_add_tail(&myself->filesystems, &map->on_filesystems);

	return 0;

errout:
	if (map != NULL)
		gsh_free(map);

	if (gpfs_fs != NULL)
		free_gpfs_filesystem(gpfs_fs);

	return retval;
}

/** @fn void gpfs_unclaim_filesystem(struct fsal_filesystem *fs)
 *  @brief Unclaim filesystem
 *  @param fs FSAL filesystem
 */
void gpfs_unclaim_filesystem(struct fsal_filesystem *fs)
{
	struct gpfs_filesystem *gpfs_fs = fs->private;
	struct glist_head *glist = NULL;
	struct glist_head *glistn = NULL;
	struct gpfs_filesystem_export_map *map = NULL;
	struct callback_arg callback =  {0};
	int reason = THREAD_STOP;

	if (gpfs_fs == NULL)
		return;

	glist_for_each_safe(glist, glistn, &gpfs_fs->exports) {
		map = glist_entry(glist, struct gpfs_filesystem_export_map,
				  on_exports);

		/* Remove this file system from mapping */
		glist_del(&map->on_filesystems);
		glist_del(&map->on_exports);

		if (map->exp->root_fs == fs) {
			LogInfo(COMPONENT_FSAL,
				"Removing root_fs %s from GPFS export",
				fs->path);
		}

		gsh_free(map);
	}

	/* Terminate GPFS upcall thread */
	callback.mountdirfd = gpfs_fs->root_fd;
	callback.reason = &reason;

	if (gpfs_ganesha(OPENHANDLE_THREAD_UPDATE, &callback) != 0)
		LogCrit(COMPONENT_FSAL,
			"Unable to stop upcall thread for %s, fd=%d, errno=%d",
			fs->path, gpfs_fs->root_fd, errno);
	else
		LogFullDebug(COMPONENT_FSAL, "Thread STOP successful");

	pthread_join(gpfs_fs->up_thread, NULL);
	free_gpfs_filesystem(gpfs_fs);
	fs->private = NULL;

	LogInfo(COMPONENT_FSAL, "GPFS Unclaiming %s", fs->path);
}

/** @fn void gpfs_unexport_filesystems(struct gpfs_fsal_export *exp)
 *  @brief Unexport filesystem
 *  @param exp FSAL export
 */
void gpfs_unexport_filesystems(struct gpfs_fsal_export *exp)
{
	struct glist_head *glist = NULL;
	struct glist_head *glistn = NULL;
	struct gpfs_filesystem_export_map *map = NULL;

	PTHREAD_RWLOCK_wrlock(&fs_lock);

	glist_for_each_safe(glist, glistn, &exp->filesystems) {
		map = glist_entry(glist, struct gpfs_filesystem_export_map,
				  on_filesystems);

		/* Remove this export from mapping */
		glist_del(&map->on_filesystems);
		glist_del(&map->on_exports);

		if (glist_empty(&map->fs->exports)) {
			LogInfo(COMPONENT_FSAL,
				"GPFS is no longer exporting filesystem %s",
				map->fs->fs->path);
			unclaim_fs(map->fs->fs);
		}
		gsh_free(map);
	}

	PTHREAD_RWLOCK_unlock(&fs_lock);
}

/** @fn fsal_status_t
 *      gpfs_create_export(struct fsal_module *fsal_hdl, void *parse_node,
 *			   struct config_error_type *err_type,
 *			   const struct fsal_up_vector *up_ops)
 * @brief create_export
 *
 *  Create an export point and return a handle to it to be kept
 *  in the export list.
 *  First lookup the fsal, then create the export and then put the fsal back.
 *  returns the export with one reference taken.
 *
 *  @return FSAL status
 */
fsal_status_t
gpfs_create_export(struct fsal_module *fsal_hdl, void *parse_node,
		   struct config_error_type *err_type,
		   const struct fsal_up_vector *up_ops)
{
	struct gpfs_fsal_export *myself =
		gsh_malloc(sizeof(struct gpfs_fsal_export));
	struct readlink_arg varg = {0};
	struct gpfs_filesystem *gpfs_fs = NULL;
	fsal_status_t status = {ERR_FSAL_NO_ERROR, 0};
	int rc;

	if (myself == NULL) {
		LogMajor(COMPONENT_FSAL, "out of memory for object");
		return fsalstat(posix2fsal_error(errno), errno);
	}

	memset(myself, 0, sizeof(struct gpfs_fsal_export));
	glist_init(&myself->filesystems);

	LogInfo(COMPONENT_FSAL, "GPFS get version is %d options 0x%X id %d",
		fsal_internal_version(), op_ctx->export->export_perms.options,
		op_ctx->export->export_id);

	rc = fsal_export_init(&myself->export);
	if (rc != 0) {
		LogMajor(COMPONENT_FSAL, "out of memory for object");
		gsh_free(myself);
		return fsalstat(posix2fsal_error(rc), rc);
	}

	gpfs_export_ops_init(&myself->export.exp_ops);
	myself->export.up_ops = up_ops;

	rc = fsal_attach_export(fsal_hdl, &myself->export.exports);
	if (rc != 0) {
		status.major = posix2fsal_error(status.minor);
		status.minor = rc;
		goto errout;	/* seriously bad */
	}
	myself->export.fsal = fsal_hdl;

	rc = populate_posix_file_systems();
	if (rc != 0) {
		status.major = posix2fsal_error(rc);
		status.minor = rc;
		LogCrit(COMPONENT_FSAL,
			"populate_posix_file_systems returned %s (%d)",
			strerror(rc), rc);
		goto detach;
	}

	rc = claim_posix_filesystems(op_ctx->export->fullpath, fsal_hdl,
				     &myself->export, gpfs_claim_filesystem,
				     gpfs_unclaim_filesystem, &myself->root_fs);
	if (rc != 0) {
		status.major = posix2fsal_error(rc);
		status.minor = rc;
		LogCrit(COMPONENT_FSAL,
			"claim_posix_filesystems(%s) returned %s (%d)",
			op_ctx->export->fullpath, strerror(rc), rc);
		goto detach;
	}

	op_ctx->fsal_export = &myself->export;

	gpfs_fs = myself->root_fs->private;
	varg.fd = gpfs_fs->root_fd;
	varg.buffer = (char *)&GPFS_write_verifier;

	rc = gpfs_ganesha(OPENHANDLE_GET_VERIFIER, &varg);
	if (rc != 0)
		LogFatal(COMPONENT_FSAL,
			 "OPENHANDLE_GET_VERIFIER failed with rc = %d", rc);

	/* if the nodeid has not been obtained, get it now */
	if (g_nodeid == 0) {
		struct grace_period_arg gpa = {0};

		gpa.mountdirfd = gpfs_fs->root_fd;
		g_nodeid = gpfs_ganesha(OPENHANDLE_GET_NODEID, &gpa);

		if (g_nodeid > 0) {
			LogFullDebug(COMPONENT_FSAL, "nodeid %d", g_nodeid);
		} else {
			LogCrit(COMPONENT_FSAL,
			    "OPENHANDLE_GET_NODEID failed rc %d", g_nodeid);
			g_nodeid = 0;
		}
	}

	myself->pnfs_ds_enabled =
		myself->export.exp_ops.fs_supports(&myself->export,
						   fso_pnfs_ds_supported);
	myself->pnfs_mds_enabled =
		myself->export.exp_ops.fs_supports(&myself->export,
						   fso_pnfs_mds_supported);
	if (myself->pnfs_ds_enabled) {
		struct fsal_pnfs_ds *pds = NULL;

		status = fsal_hdl->m_ops.fsal_pnfs_ds(fsal_hdl, parse_node,
						      &pds);

		if (FSAL_IS_ERROR(status))
			goto detach;

		/* special case: server_id matches export_id */
		pds->id_servers = op_ctx->export->export_id;
		pds->mds_export = op_ctx->export;

		if (!pnfs_ds_insert(pds)) {
			LogCrit(COMPONENT_CONFIG,
				"Server id %d already in use.",
				pds->id_servers);
			status.major = ERR_FSAL_EXIST;
			fsal_pnfs_ds_fini(pds);
			gsh_free(pds);
			goto detach;
		}

		LogInfo(COMPONENT_FSAL,
			"gpfs_fsal_create: pnfs ds was enabled for [%s]",
			op_ctx->export->fullpath);
	}

	if (myself->pnfs_mds_enabled) {
		LogInfo(COMPONENT_FSAL,
			"gpfs_fsal_create: pnfs mds was enabled for [%s]",
			op_ctx->export->fullpath);
		export_ops_pnfs(&myself->export.exp_ops);
	}

	myself->use_acl = !(op_ctx->export->options &
				EXPORT_OPTION_DISABLE_ACL);

	return status;
detach:
	fsal_detach_export(fsal_hdl, &myself->export.exports);
errout:
	free_export_ops(&myself->export);
	gsh_free(myself);
	return status;
}
