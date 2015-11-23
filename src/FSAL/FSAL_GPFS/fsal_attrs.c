/** @file fsal_attrs.c
 *  @brief GPFS FSAL attribute functions
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301 USA
 *
 * ---------------------------------------
 */

#include "fsal.h"
#include "fsal_internal.h"
#include "fsal_convert.h"
#include "gpfs_methods.h"
#include <sys/types.h>
#include <unistd.h>
#include <utime.h>
#include <sys/time.h>
#include "export_mgr.h"

/** @fn fsal_status_t
 *      GPFSFSAL_fs_loc(struct fsal_export *export, struct gpfs_filesystem *gpfs_fs,
 *			const struct req_op_context *op_ctx,
 *			struct gpfs_file_handle *gpfs_fh,
 *			struct attrlist *obj_attr,
 *			struct fs_locations4 *fs_locs)
 *  @param export FSAL export
 *  @param gpfs_fs GPFS filesystem
 *  @param op_ctx Request op context
 *  @param gpfs_fh GPFS file handle
 *  @param obj_attr Object attributes
 *  @param fs_locs FS locations
 *  @return FSAL status
 *
 *  @brief Get fs_locations attribute for the object specified by its filehandle.
 *
 */
fsal_status_t
GPFSFSAL_fs_loc(struct fsal_export *export, struct gpfs_filesystem *gpfs_fs,
		const struct req_op_context *op_ctx,
		struct gpfs_file_handle *gpfs_fh, struct attrlist *obj_attr,
		struct fs_locations4 *fs_locs)
{
	struct fs_loc_arg fs_loc = {0};
	struct fs_location4 *loc_val = fs_locs->locations.locations_val;
	int rc = 0;

	fs_loc.fs_path_len = fs_locs->fs_root.pathname4_val->utf8string_len;
	fs_loc.fs_path = fs_locs->fs_root.pathname4_val->utf8string_val;
	fs_loc.fs_server_len = loc_val->server.server_val->utf8string_len;
	fs_loc.fs_server = loc_val->server.server_val->utf8string_val;
	fs_loc.fs_root_len = loc_val->rootpath.pathname4_val->utf8string_len;
	fs_loc.fs_root = loc_val->rootpath.pathname4_val->utf8string_val;
	fs_loc.mountdirfd = gpfs_fs->root_fd;
	fs_loc.handle = gpfs_fh;

	rc = gpfs_ganesha(OPENHANDLE_FS_LOCATIONS, &fs_loc);
	if (rc) {
		LogDebug(COMPONENT_FSAL,
			 "gpfs_ganesha: FS_LOCATIONS returned, rc %d errno %d",
			 rc, errno);
		return fsalstat(ERR_FSAL_ATTRNOTSUPP, 0);
	}

	fs_locs->fs_root.pathname4_val->utf8string_len = fs_loc.fs_path_len;
	loc_val->server.server_val->utf8string_len = fs_loc.fs_server_len;
	loc_val->rootpath.pathname4_val->utf8string_len = fs_loc.fs_root_len;

	LogDebug(COMPONENT_FSAL,
		 "gpfs_ganesha: FS_LOCATIONS root=%s path=%s server=%s",
		 fs_loc.fs_root, fs_loc.fs_path, fs_loc.fs_server);

	return fsalstat(ERR_FSAL_NO_ERROR, 0);
}

/** @fn fsal_status_t
 *	GPFSFSAL_getattrs(struct fsal_export *export,
 *			  struct gpfs_filesystem *gpfs_fs,
 *			  const struct req_op_context *op_ctx,
 *			  struct gpfs_file_handle *gpfs_fh,
 *			  struct attrlist *obj_attr)
 *  @param export FSAL export
 *  @param gpfs_fs GPFS filesystem
 *  @param op_ctx Request op context
 *  @param gpfs_fh GPFS file handle
 *  @param obj_attr Object attributes
 *  @return FSAL status
 *
 *  @brief Get attributes for the object specified by its filehandle.
 */
fsal_status_t
GPFSFSAL_getattrs(struct fsal_export *export, struct gpfs_filesystem *gpfs_fs,
		  const struct req_op_context *op_ctx,
		  struct gpfs_file_handle *gpfs_fh, struct attrlist *obj_attr)
{
	struct gpfs_fsal_export *gpfs_export =
		container_of(export, struct gpfs_fsal_export, export);
	gpfsfsal_xstat_t buffxstat = {0};
	uint32_t exp_tattr = 0;
	bool expire = op_ctx->export->expire_time_attr > 0;
	fsal_status_t status = fsal_get_xstat_by_handle(gpfs_fs->root_fd,
							gpfs_fh, &buffxstat,
							&exp_tattr, expire,
							gpfs_export->use_acl);

	if (FSAL_IS_ERROR(status))
		return status;

	/* convert attributes */
	if (exp_tattr != 0)
		obj_attr->expire_time_attr = exp_tattr;

	/* Assume if fsid = 0.0, then old GPFS didn't fill it in, in that
	 * case, fill in from the object's filesystem.
	 */
	if (buffxstat.fsal_fsid.major == 0 && buffxstat.fsal_fsid.minor == 0)
		buffxstat.fsal_fsid = gpfs_fs->fs->fsid;

	status = gpfsfsal_xstat_2_fsal_attributes(&buffxstat, obj_attr,
						  gpfs_export->use_acl);

	if (FSAL_IS_ERROR(status)) {
		FSAL_CLEAR_MASK(obj_attr->mask);
		FSAL_SET_MASK(obj_attr->mask, ATTR_RDATTR_ERR);
	}

	return status;
}

/** @fn fsal_status_t
 *	GPFSFSAL_statfs(int mountdirfd, struct fsal_obj_handle *obj_hdl,
 *			struct statfs *buf)
 *  @param mountdirfs Mounted filesystem
 *  @param obj_hdl Object handle
 *  @param buf reference to statfs structure
 *  @return FSAL status
 *
 *  @brief Get fs attributes for the object specified by its filehandle.
 */
fsal_status_t
GPFSFSAL_statfs(int mountdirfd, struct fsal_obj_handle *obj_hdl,
		struct statfs *buf)
{
	struct gpfs_fsal_obj_handle *myself =
		container_of(obj_hdl, struct gpfs_fsal_obj_handle, obj_handle);
	struct statfs_arg sarg = {0};
	int rc = 0;
	int errsv = 0;

	sarg.handle = myself->handle;
	sarg.mountdirfd = mountdirfd;
	sarg.buf = buf;

	rc = gpfs_ganesha(OPENHANDLE_STATFS_BY_FH, &sarg);
	if (rc < 0) {
		errsv = errno;
		LogFullDebug(COMPONENT_FSAL,
			     "OPENHANDLE_STATFS_BY_FH returned: rc %d", rc);
		if (errsv == EUNATCH)
			LogFatal(COMPONENT_FSAL, "GPFS Returned EUNATCH");
		return fsalstat(posix2fsal_error(errsv), errsv);
	}

	return fsalstat(ERR_FSAL_NO_ERROR, 0);
}

/** @fn fsal_status_t
 *	GPFSFSAL_setattrs(struct fsal_obj_handle *dir_hdl,
 *			  const struct req_op_context *ro_ctx,
 *			  struct attrlist *obj_attr)
 *  @param dir_hdl The handle of the object to get parameters.
 *  @param ro_ctx Authentication context for the operation (user,...).
 *  @param obj_attr The post operation attributes for the object.
 *		    As input, it defines the attributes that the caller
 *		    wants to retrieve (by positioning flags into this structure)
 *		    and the output is built considering this input
 *		    (it fills the structure according to the flags it contains).
 *		    May be NULL.
 *  @return FSAL status
 *
 *  @brief Set attributes for the object specified by its filehandle.
 */
fsal_status_t
GPFSFSAL_setattrs(struct fsal_obj_handle *dir_hdl,
		  const struct req_op_context *ro_ctx,
		  struct attrlist *obj_attr)
{
	struct gpfs_fsal_obj_handle *myself = NULL;
	gpfsfsal_xstat_t buffxstat = {0};
	struct gpfs_filesystem *gpfs_fs = NULL;
	struct gpfs_fsal_export *gpfs_export = NULL;
	fsal_status_t status = {ERR_FSAL_NO_ERROR, 0};
	bool use_acl = false;
	int attr_valid = 0;  /* should stat or acl or both be changed. */
	int attr_changed = 0; /* which attribute in stat should be changed. */

	/* sanity checks.
	 * note : object_attributes is optional.
	 */
	if (!dir_hdl || !ro_ctx || !obj_attr)
		return fsalstat(ERR_FSAL_FAULT, 0);

	myself = container_of(dir_hdl, struct gpfs_fsal_obj_handle, obj_handle);
	gpfs_fs = dir_hdl->fs->private;
	gpfs_export = container_of(ro_ctx->fsal_export, struct gpfs_fsal_export,
				   export);

	use_acl = gpfs_export->use_acl;

	/* First, check that FSAL attributes changes are allowed. */
	/* Is it allowed to change times ? */
	if (!ro_ctx->fsal_export->exp_ops.fs_supports(ro_ctx->fsal_export,
						      fso_cansettime)) {
		if (obj_attr->mask &
		    (ATTR_ATIME | ATTR_CREATION | ATTR_CTIME | ATTR_MTIME |
		     ATTR_MTIME_SERVER | ATTR_ATIME_SERVER)) {
			/* handled as an unsettable attribute. */
			return fsalstat(ERR_FSAL_INVAL, 0);
		}
	}

	/* apply umask, if mode attribute is to be changed */
	if (FSAL_TEST_MASK(obj_attr->mask, ATTR_MODE)) {
		obj_attr->mode &=
		    ~ro_ctx->fsal_export->exp_ops.fs_umask(ro_ctx->fsal_export);
	}

  /**************
   *  TRUNCATE  *
   **************/
	if (FSAL_TEST_MASK(obj_attr->mask, ATTR_SIZE)) {
		attr_changed |= XATTR_SIZE;
		/* Fill wanted mode. */
		buffxstat.buffstat.st_size = obj_attr->filesize;
		LogDebug(COMPONENT_FSAL, "current size = %llu, new size = %llu",
			 (unsigned long long)myself->attributes.filesize,
			 (unsigned long long)buffxstat.buffstat.st_size);
	}

  /*******************
   *  SPACE RESERVED *
   *******************/
	if (FSAL_TEST_MASK(obj_attr->mask, ATTR4_SPACE_RESERVED)) {
		attr_changed |= XATTR_SPACE_RESERVED;
		/* Fill wanted mode. */
		buffxstat.buffstat.st_size = obj_attr->filesize;
		LogDebug(COMPONENT_FSAL, "current size = %llu, new size = %llu",
			 (unsigned long long)myself->attributes.filesize,
			 (unsigned long long)buffxstat.buffstat.st_size);
	}

  /***********
   *  CHMOD  *
   ***********/
	if (FSAL_TEST_MASK(obj_attr->mask, ATTR_MODE) &&
	    (dir_hdl->type != SYMBOLIC_LINK)) {
		/* The POSIX chmod call don't affect the symlink object, but
		 * the entry it points to. So we must ignore it.
		 */
		attr_changed |= XATTR_MODE;
		/* Fill wanted mode. */
		buffxstat.buffstat.st_mode = fsal2unix_mode(obj_attr->mode);
		LogDebug(COMPONENT_FSAL, "current mode = %o, new mode = %o",
			 fsal2unix_mode(myself->attributes.mode),
			 buffxstat.buffstat.st_mode);
	}

  /***********
   *  CHOWN  *
   ***********/
	/* Fill wanted owner. */
	if (FSAL_TEST_MASK(obj_attr->mask, ATTR_OWNER)) {
		attr_changed |= XATTR_UID;
		buffxstat.buffstat.st_uid = (int)obj_attr->owner;
		LogDebug(COMPONENT_FSAL, "current uid = %ld, new uid = %d",
			 myself->attributes.owner, buffxstat.buffstat.st_uid);
	}

	/* Fill wanted group. */
	if (FSAL_TEST_MASK(obj_attr->mask, ATTR_GROUP)) {
		attr_changed |= XATTR_GID;
		buffxstat.buffstat.st_gid = (int)obj_attr->group;
		LogDebug(COMPONENT_FSAL, "current gid = %ld, new gid = %d",
			 myself->attributes.group, buffxstat.buffstat.st_gid);
	}

  /***********
   *  UTIME  *
   ***********/
	/* Fill wanted atime. */
	if (FSAL_TEST_MASK(obj_attr->mask, ATTR_ATIME)) {
		attr_changed |= XATTR_ATIME;
		buffxstat.buffstat.st_atime = (time_t) obj_attr->atime.tv_sec;
		buffxstat.buffstat.st_atim.tv_nsec = obj_attr->atime.tv_nsec;
		LogDebug(COMPONENT_FSAL, "current atime = %lu, new atime = %lu",
			 (unsigned long)myself->attributes.atime.tv_sec,
			 (unsigned long)buffxstat.buffstat.st_atime);
	}

	/* Fill wanted mtime. */
	if (FSAL_TEST_MASK(obj_attr->mask, ATTR_MTIME)) {
		attr_changed |= XATTR_MTIME;
		buffxstat.buffstat.st_mtime = (time_t) obj_attr->mtime.tv_sec;
		buffxstat.buffstat.st_mtim.tv_nsec = obj_attr->mtime.tv_nsec;
		LogDebug(COMPONENT_FSAL, "current mtime = %lu, new mtime = %lu",
			 (unsigned long)myself->attributes.mtime.tv_sec,
			 (unsigned long)buffxstat.buffstat.st_mtime);
	}

	/* Asking to set atime to NOW */
	if (FSAL_TEST_MASK(obj_attr->mask, ATTR_ATIME_SERVER)) {
		attr_changed |= XATTR_ATIME | XATTR_ATIME_NOW;
		LogDebug(COMPONENT_FSAL, "current atime = %lu, new atime = NOW",
			 (unsigned long)myself->attributes.atime.tv_sec);
	}

	/* Asking to set atime to NOW */
	if (FSAL_TEST_MASK(obj_attr->mask, ATTR_MTIME_SERVER)) {
		attr_changed |= XATTR_MTIME | XATTR_MTIME_NOW;
		LogDebug(COMPONENT_FSAL, "current mtime = %lu, new mtime = NOW",
			 (unsigned long)myself->attributes.atime.tv_sec);
	}

	/* If any stat changed, indicate that */
	if (attr_changed != 0)
		attr_valid |= XATTR_STAT;

	if (use_acl && FSAL_TEST_MASK(obj_attr->mask, ATTR_ACL)) {
		if (obj_attr->acl == NULL) {
			LogCrit(COMPONENT_FSAL, "setattr acl is NULL");
			return fsalstat(ERR_FSAL_FAULT, 0);
		}

		attr_valid |= XATTR_ACL;
		LogDebug(COMPONENT_FSAL, "setattr acl = %p",
			 obj_attr->acl);

		/* Convert FSAL ACL to GPFS NFS4 ACL and fill buffer. */
		status = fsal_acl_2_gpfs_acl(dir_hdl, obj_attr->acl,
					     &buffxstat);

		if (FSAL_IS_ERROR(status))
			return status;
	}

	/* If there is any change in stat or acl or both, send it down to fs. */
	if (attr_valid != 0)
		status = fsal_set_xstat_by_handle(gpfs_fs->root_fd, ro_ctx,
						  myself->handle, attr_valid,
						  attr_changed, &buffxstat);

	return status;
}
