/*
 * @file    fsal_internal.h
 * @brief   Extern definitions for variables that are
 *          defined in fsal_internal.c.
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

#include <sys/stat.h>
#include "fsal.h"
#include "gsh_list.h"
#include "fsal_types.h"
#include "fcntl.h"
#include "include/gpfs_nfs.h"
#include "fsal_up.h"

void gpfs_handle_ops_init(struct fsal_obj_ops *ops);
bool fsal_error_is_event(fsal_status_t status);
bool fsal_error_is_info(fsal_status_t status);
void set_gpfs_verifier(verifier4 *verifier);

/** @struct gpfs_ds
 *  @brief The full, 'private' DS (data server) handle
 */
struct gpfs_ds {
	struct fsal_ds_handle ds;	/** Public DS handle */
	struct gpfs_file_handle wire;	/** Wire data */
	struct gpfs_filesystem *gpfs_fs; /** filesystem handle belongs to */
	bool connected;		/** True if the handle has been connected */
};


/** @def GPFS_SUPPORTED_ATTRIBUTES
 *  @brief defined the set of attributes supported with POSIX
 */
#define GPFS_SUPPORTED_ATTRIBUTES (                              \
		ATTR_TYPE     | ATTR_SIZE     |                  \
		ATTR_FSID     | ATTR_FILEID   |                  \
		ATTR_MODE     | ATTR_NUMLINKS | ATTR_OWNER     | \
		ATTR_GROUP    | ATTR_ATIME    | ATTR_RAWDEV    | \
		ATTR_CTIME    | ATTR_MTIME    | ATTR_SPACEUSED | \
		ATTR_CHGTIME | ATTR_ACL | ATTR4_SPACE_RESERVED | \
		ATTR4_FS_LOCATIONS)

/** @def GPFS_ACL_BUF_SIZE
 *  @briefDefine the buffer size for GPFS NFS4 ACL.
 */
#define GPFS_ACL_BUF_SIZE 0x1000

/** @def GPFS_FSID_TYPE
 *  @brief Define the standard fsid_type for GPFS
 */
#define GPFS_FSID_TYPE FSID_MAJOR_64

/** @struct fsal_xstat__
 *
 * A set of buffers to retrieve multiple attributes at the same time.
 */
typedef struct fsal_xstat__ {
	int attr_valid;
	struct stat buffstat;
	fsal_fsid_t fsal_fsid;
	char buffacl[GPFS_ACL_BUF_SIZE];
} gpfsfsal_xstat_t;  /** @typedef gpfsfsal_xstat_t */

/** @fn static inline size_t gpfs_sizeof_handle(
 *		const struct gpfs_file_handle *hdl)
 *  @param gpfs_fh file handle of file
 *  @return Size
 */
static inline size_t gpfs_sizeof_handle(const struct gpfs_file_handle *gpfs_fh)
{
	return offsetof(struct gpfs_file_handle, f_handle)+gpfs_fh->handle_size;
}

void export_ops_init(struct export_ops *ops);
void handle_ops_init(struct fsal_obj_ops *ops);
void pnfs_ds_ops_init(struct fsal_pnfs_ds_ops *ops);
void export_ops_pnfs(struct export_ops *ops);
void handle_ops_pnfs(struct fsal_obj_ops *ops);

fsal_status_t fsal_internal_close(int fd, void *owner, int cflags);

int fsal_internal_version(void);

fsal_status_t fsal_internal_get_handle(const char *fs_path,
				       struct gpfs_file_handle *gpfs_fh);

fsal_status_t fsal_internal_get_handle_at(int fd, const char *fs_name,
					  struct gpfs_file_handle *gpfs_fh);

fsal_status_t gpfsfsal_xstat_2_fsal_attributes(gpfsfsal_xstat_t *gpfs_buf,
					       struct attrlist *fsal_attr,
					       bool use_acl);

fsal_status_t fsal_internal_handle2fd(int dir_fd,
				      struct gpfs_file_handle *gpfs_fh,
				      int *fd, int oflags, bool reopen);

fsal_status_t fsal_internal_handle2fd_at(int dir_fd,
					 struct gpfs_file_handle *gpfs_fh,
					 int *fd, int oflags, bool reopen);

fsal_status_t fsal_internal_get_fh(int dir_fd, struct gpfs_file_handle *gpfs_fh,
				   const char *fs_name,
				   struct gpfs_file_handle *gpfs_fh_out);

fsal_status_t fsal_readlink_by_handle(int dir_fd,
				      struct gpfs_file_handle *gpfs_fh,
				      char *buf, size_t *maxlen);

fsal_status_t fsal_internal_fd2handle(int fd, struct gpfs_file_handle *gpfs_fh);

fsal_status_t fsal_internal_link_fh(int dir_fd,
				    struct gpfs_file_handle *gpfs_fh_tgt,
				    struct gpfs_file_handle *gpfs_fh,
				    const char *link_name);

fsal_status_t fsal_internal_stat_name(int dir_fd,
				      struct gpfs_file_handle *gpfs_fh,
				      const char *stat_name, struct stat *buf);

fsal_status_t fsal_internal_unlink(int dir_fd, struct gpfs_file_handle *gpfs_fh,
				   const char *stat_name, struct stat *buf);

fsal_status_t fsal_internal_create(struct fsal_obj_handle *dir_hdl,
				   const char *stat_name, mode_t mode,
				   dev_t dev, struct gpfs_file_handle *gpfs_fh,
				   struct stat *buf);

fsal_status_t fsal_internal_rename_fh(int dir_fd,
				      struct gpfs_file_handle *gpfs_fh_old,
				      struct gpfs_file_handle *gpfs_fh_new,
				      const char *old_name,
				      const char *new_name);

fsal_status_t fsal_get_xstat_by_handle(int dir_fd,
				       struct gpfs_file_handle *gpfs_fh,
				       gpfsfsal_xstat_t *buffxstat,
				       uint32_t *exp_tattr, bool expire,
				       bool use_acl);

fsal_status_t fsal_set_xstat_by_handle(int dir_fd,
				       const struct req_op_context *op_ctx,
				       struct gpfs_file_handle *gpfs_fh,
				       int attr_valid, int attr_changed,
				       gpfsfsal_xstat_t *buffxstat);

fsal_status_t fsal_trucate_by_handle(int dir_fd,
				     const struct req_op_context *op_ctx,
				     struct gpfs_file_handle *gpfs_fh,
				     u_int64_t size);

fsal_status_t fsal_acl_2_gpfs_acl(struct fsal_obj_handle *dir_hdl,
				  fsal_acl_t *fsal_acl,
				  gpfsfsal_xstat_t *gpfs_buf);

/* All the call to FSAL to be wrapped */

fsal_status_t GPFSFSAL_getattrs(struct fsal_export *export,
				struct gpfs_filesystem *gpfs_fs,
				const struct req_op_context *op_ctx,
				struct gpfs_file_handle *gpfs_fh,
				struct attrlist *fsal_attr);

fsal_status_t GPFSFSAL_fs_loc(struct fsal_export *export,
				struct gpfs_filesystem *gpfs_fs,
				const struct req_op_context *op_ctx,
				struct gpfs_file_handle *gpfs_fh,
				struct attrlist *fasl_attr,
				struct fs_locations4 *fs_loc);

fsal_status_t GPFSFSAL_statfs(int fd,
			      struct fsal_obj_handle *fasl_hdl,
			      struct statfs *buf);

fsal_status_t GPFSFSAL_setattrs(struct fsal_obj_handle *dir_hdl,
				const struct req_op_context *op_ctx,
				struct attrlist *fsal_attr);

fsal_status_t GPFSFSAL_create(struct fsal_obj_handle *dir_hdl,
			      const char *filename,
			      const struct req_op_context *op_ctx,
			      uint32_t accessmode,
			      struct gpfs_file_handle *gpfs_fh,
			      struct attrlist *fsal_attr);

fsal_status_t GPFSFSAL_mkdir(struct fsal_obj_handle *dir_hdl,
			     const char *dirname,
			     const struct req_op_context *op_ctx,
			     uint32_t accessmode,
			     struct gpfs_file_handle *gpfs_fh,
			     struct attrlist *fsal_attr);

fsal_status_t GPFSFSAL_link(struct fsal_obj_handle *dir_hdl,
			    struct gpfs_file_handle *gpfs_fh,
			    const char *linkname,
			    const struct req_op_context *op_ctx,
			    struct attrlist *fsal_attr);

fsal_status_t GPFSFSAL_mknode(struct fsal_obj_handle *dir_hdl,
			      const char *nodename,
			      const struct req_op_context *op_ctx,
			      uint32_t accessmode,
			      mode_t nodetype, fsal_dev_t *dev,
			      struct gpfs_file_handle *p_object_handle,
			      struct attrlist *fsal_attr);

fsal_status_t GPFSFSAL_open(struct fsal_obj_handle *dir_hdl,
			    const struct req_op_context *op_ctx,
			    fsal_openflags_t openflags,
			    int *file_descriptor,
			    struct attrlist *fsal_attr, bool reopen);

fsal_status_t GPFSFSAL_read(int fd, uint64_t offset, size_t buffer_size,
			    caddr_t buffer, size_t *read_amount,
			    bool *end_of_file);

fsal_status_t GPFSFSAL_write(int fd, uint64_t offset, size_t buffer_size,
			     caddr_t buffer, size_t *write_amount,
			     bool *fsal_stable,
			     const struct req_op_context *op_ctx);

fsal_status_t GPFSFSAL_alloc(int fd, uint64_t offset, uint64_t length,
			     bool options);

fsal_status_t GPFSFSAL_lookup(const struct req_op_context *op_ctx,
			      struct fsal_obj_handle *parent,
			      const char *filename, struct attrlist *fsal_attr,
			      struct gpfs_file_handle *gpfs_fh,
			      struct fsal_filesystem **new_fs);

fsal_status_t GPFSFSAL_lock_op(struct fsal_export *export,
			       struct fsal_obj_handle *obj_hdl,
			       void *p_owner, fsal_lock_op_t lock_op,
			       fsal_lock_param_t request_lock,
			       fsal_lock_param_t *conflicting_lock);

fsal_status_t GPFSFSAL_share_op(int mntfd, int fd, void *p_owner,
				fsal_share_param_t request_share);

fsal_status_t GPFSFSAL_rename(struct fsal_obj_handle *old_hdl,
			      const char *old_name,
			      struct fsal_obj_handle *new_hdl,
			      const char *new_name,
			      const struct req_op_context *op_ctx);

fsal_status_t GPFSFSAL_readlink(struct fsal_obj_handle *dir_hdl,
				const struct req_op_context *op_ctx,
				char *link_content, size_t *link_len,
				struct attrlist *fsal_attr);

fsal_status_t GPFSFSAL_symlink(struct fsal_obj_handle *dir_hdl,
			       const char *linkname, const char *linkcontent,
			       const struct req_op_context *op_ctx,
			       uint32_t accessmode,
			       struct gpfs_file_handle *link_handle,
			       struct attrlist *fsal_attr);

fsal_status_t GPFSFSAL_unlink(struct fsal_obj_handle *dir_hdl,
			      const char *object_name,
			      const struct req_op_context *op_ctx);

void *GPFSFSAL_UP_Thread(void *Arg);

size_t fs_da_addr_size(struct fsal_module *fsal_hdl);

nfsstat4 getdeviceinfo(struct fsal_module *fsal_hdl,
		       XDR *da_addr_body, const layouttype4 type,
		       const struct pnfs_deviceid *deviceid);
