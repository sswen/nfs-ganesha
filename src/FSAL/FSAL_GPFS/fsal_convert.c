/** @file fsal_convert.c
 *  @brief GPFS FSAL module convert functions
 *
 * vim:noexpandtab:shiftwidth=8:tabstop=8:
 *
 * HPSS-FSAL type translation functions.
 */

#include "config.h"
#include "fsal_convert.h"
#include "fsal_internal.h"
#include "nfs4_acls.h"
#include "include/gpfs.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>

static int gpfs_acl_2_fsal_acl(struct attrlist *p_object_attributes,
			       gpfs_acl_t *p_gpfsacl);

/**
 *  @brief convert GPFS xstat to FSAl attributes
 *
 *  @param gpfs_buf Reference to GPFS stat buffer
 *  @param fsal_attr Reference to attribute list
 *  @param use_acl Bool whether ACL are used
 *  @return FSAL status
 *
 *  Same function as posixstat64_2_fsal_attributes. When NFS4 ACL support
 *  is enabled, this will replace posixstat64_2_fsal_attributes.
 */
fsal_status_t
gpfsfsal_xstat_2_fsal_attributes(gpfsfsal_xstat_t *gpfs_buf,
				 struct attrlist *fsal_attr, bool use_acl)
{
	struct stat *buf;

	if (!gpfs_buf || !fsal_attr)
		return fsalstat(ERR_FSAL_FAULT, 0);

	buf = &gpfs_buf->buffstat;

	LogDebug(COMPONENT_FSAL, "inode %ld", buf->st_ino);

	/* Fills the output struct */
	if (FSAL_TEST_MASK(fsal_attr->mask, ATTR_TYPE)) {
		fsal_attr->type = posix2fsal_type(buf->st_mode);
		LogFullDebug(COMPONENT_FSAL, "type = 0x%x",
			     fsal_attr->type);
	}

	if (FSAL_TEST_MASK(fsal_attr->mask, ATTR_SIZE)) {
		fsal_attr->filesize = buf->st_size;
		LogFullDebug(COMPONENT_FSAL, "filesize = %llu",
			     (unsigned long long)fsal_attr->filesize);
	}

	if (FSAL_TEST_MASK(fsal_attr->mask, ATTR_FSID)) {
		fsal_attr->fsid = gpfs_buf->fsal_fsid;
		LogFullDebug(COMPONENT_FSAL,
			     "fsid=0x%016"PRIx64".0x%016"PRIx64,
			     fsal_attr->fsid.major,
			     fsal_attr->fsid.minor);
	}

	if (FSAL_TEST_MASK(fsal_attr->mask, ATTR_ACL)) {
		fsal_attr->acl = NULL;
		if (use_acl && gpfs_buf->attr_valid & XATTR_ACL) {
			/* ACL is valid, so try to convert fsal acl. */
			gpfs_acl_2_fsal_acl(fsal_attr,
					    (gpfs_acl_t *) gpfs_buf->buffacl);
		}
		LogFullDebug(COMPONENT_FSAL, "acl = %p", fsal_attr->acl);
	}

	if (FSAL_TEST_MASK(fsal_attr->mask, ATTR_FILEID)) {
		fsal_attr->fileid = (uint64_t) (buf->st_ino);
		LogFullDebug(COMPONENT_FSAL, "fileid = %" PRIu64,
			     fsal_attr->fileid);
	}

	if (FSAL_TEST_MASK(fsal_attr->mask, ATTR_MODE)) {
		fsal_attr->mode = unix2fsal_mode(buf->st_mode);
		LogFullDebug(COMPONENT_FSAL, "mode = %"PRIu32,
			     fsal_attr->mode);
	}

	if (FSAL_TEST_MASK(fsal_attr->mask, ATTR_NUMLINKS)) {
		fsal_attr->numlinks = buf->st_nlink;
		LogFullDebug(COMPONENT_FSAL, "numlinks = %u",
			     fsal_attr->numlinks);
	}

	if (FSAL_TEST_MASK(fsal_attr->mask, ATTR_OWNER)) {
		fsal_attr->owner = buf->st_uid;
		LogFullDebug(COMPONENT_FSAL, "owner = %" PRIu64,
			     fsal_attr->owner);
	}

	if (FSAL_TEST_MASK(fsal_attr->mask, ATTR_GROUP)) {
		fsal_attr->group = buf->st_gid;
		LogFullDebug(COMPONENT_FSAL, "group = %" PRIu64,
			     fsal_attr->group);
	}

	if (FSAL_TEST_MASK(fsal_attr->mask, ATTR_ATIME)) {
		fsal_attr->atime =
		    posix2fsal_time(buf->st_atime, buf->st_atim.tv_nsec);
		LogFullDebug(COMPONENT_FSAL, "atime = %lu",
			     fsal_attr->atime.tv_sec);
	}

	if (FSAL_TEST_MASK(fsal_attr->mask, ATTR_CTIME)) {
		fsal_attr->ctime =
		    posix2fsal_time(buf->st_ctime, buf->st_ctim.tv_nsec);
		LogFullDebug(COMPONENT_FSAL, "ctime = %lu",
			     fsal_attr->ctime.tv_sec);
	}

	if (FSAL_TEST_MASK(fsal_attr->mask, ATTR_MTIME)) {
		fsal_attr->mtime =
		    posix2fsal_time(buf->st_mtime, buf->st_mtim.tv_nsec);
		LogFullDebug(COMPONENT_FSAL, "mtime = %lu",
			     fsal_attr->mtime.tv_sec);
	}

	if (FSAL_TEST_MASK(fsal_attr->mask, ATTR_CHGTIME)) {
		if (buf->st_mtime == buf->st_ctime) {
			if (buf->st_mtim.tv_nsec > buf->st_ctim.tv_nsec)
				fsal_attr->chgtime =
				    posix2fsal_time(buf->st_mtime,
						    buf->st_mtim.tv_nsec);
			else
				fsal_attr->chgtime =
				    posix2fsal_time(buf->st_ctime,
						    buf->st_ctim.tv_nsec);
		} else if (buf->st_mtime > buf->st_ctime) {
			fsal_attr->chgtime = posix2fsal_time(buf->st_mtime,
							buf->st_mtim.tv_nsec);
		} else {
			fsal_attr->chgtime = posix2fsal_time(buf->st_ctime,
							buf->st_ctim.tv_nsec);
		}
		fsal_attr->change = (uint64_t) fsal_attr->chgtime.tv_sec +
				    (uint64_t) fsal_attr->chgtime.tv_nsec;

		LogFullDebug(COMPONENT_FSAL, "chgtime = %lu",
			     fsal_attr->chgtime.tv_sec);

	}

	if (FSAL_TEST_MASK(fsal_attr->mask, ATTR_SPACEUSED)) {
		fsal_attr->spaceused = buf->st_blocks * S_BLKSIZE;
		LogFullDebug(COMPONENT_FSAL, "spaceused = %llu",
			     (unsigned long long)fsal_attr->spaceused);
	}

	if (FSAL_TEST_MASK(fsal_attr->mask, ATTR_RAWDEV)) {
		fsal_attr->rawdev = posix2fsal_devt(buf->st_rdev);
		LogFullDebug(COMPONENT_FSAL, "rawdev major = %u, minor = %u",
			     (unsigned int)fsal_attr->rawdev.major,
			     (unsigned int)fsal_attr->rawdev.minor);
	}

	return fsalstat(ERR_FSAL_NO_ERROR, 0);
}

/* Covert GPFS NFS4 ACLs to FSAL ACLs, and set the ACL
 * pointer of attribute. */
static int gpfs_acl_2_fsal_acl(struct attrlist *obj_attr, gpfs_acl_t *gpfs_acl)
{
	fsal_acl_status_t acl_status = 0;
	fsal_acl_data_t acl_data = {0};
	fsal_ace_t *ace;
	fsal_acl_t *acl;
	gpfs_ace_v4_t *ace_gpfs;

	if (!obj_attr || !gpfs_acl)
		return ERR_FSAL_FAULT;

	/* everything has been copied ! */
	/* Create fsal acl data. */
	acl_data.naces = gpfs_acl->acl_nace;
	acl_data.aces = (fsal_ace_t *) nfs4_ace_alloc(acl_data.naces);

	/* Fill fsal acl data from gpfs acl. */
	for (ace = acl_data.aces, ace_gpfs = gpfs_acl->ace_v4;
		ace < acl_data.aces + acl_data.naces; ace++, ace_gpfs++) {
		ace->type = ace_gpfs->aceType;
		ace->flag = ace_gpfs->aceFlags;
		ace->iflag = ace_gpfs->aceIFlags;
		ace->perm = ace_gpfs->aceMask;

		if (IS_FSAL_ACE_SPECIAL_ID(*ace)) /* Record special user. */
			ace->who.uid = ace_gpfs->aceWho;
		else if (IS_FSAL_ACE_GROUP_ID(*ace))
			ace->who.gid = ace_gpfs->aceWho;
		else    /* Record user. */
			ace->who.uid = ace_gpfs->aceWho;

		LogMidDebug(COMPONENT_FSAL,
			    "gpfs_acl_2_fsal_acl: fsal ace: type = 0x%x, flag = 0x%x, perm = 0x%x, special = %d, %s = 0x%x",
			    ace->type, ace->flag, ace->perm,
			    IS_FSAL_ACE_SPECIAL_ID(*ace),
			    GET_FSAL_ACE_WHO_TYPE(*ace),
			    GET_FSAL_ACE_WHO(*ace));
	}

	/* Create a new hash table entry for fsal acl. */
	acl = nfs4_acl_new_entry(&acl_data, &acl_status);
	LogMidDebug(COMPONENT_FSAL, "fsal acl = %p, fsal_acl_status = %u", acl,
		    acl_status);

	if (acl == NULL) {
		LogCrit(COMPONENT_FSAL,
			"gpfs_acl_2_fsal_acl: failed to create a new acl entry");
	return ERR_FSAL_FAULT;
	}

	obj_attr->acl = acl;  /* Add fsal acl to attribute. */

	return ERR_FSAL_NO_ERROR;
}

/** @fn fsal_status_t
 *     fsal_acl_2_gpfs_acl(struct fsal_obj_handle *dir_hdl, fsal_acl_t *fsal_acl,
 *                         gpfsfsal_xstat_t *gpfs_buf)
 *  @param dir_hdl Object handle
 *  @param fsal_acl GPFS access control list
 *  @param gpfs_buf Reference to GPFS stat buffer
 *  @return FSAL status
 *
 *  @brief Covert FSAL ACLs to GPFS NFS4 ACLs.
 */
fsal_status_t
fsal_acl_2_gpfs_acl(struct fsal_obj_handle *dir_hdl, fsal_acl_t *fsal_acl,
		    gpfsfsal_xstat_t *gpfs_buf)
{
	gpfs_acl_t *gpfs_acl = (gpfs_acl_t *) gpfs_buf->buffacl;
	fsal_ace_t *ace;
	int i;

	gpfs_acl->acl_level = 0;
	gpfs_acl->acl_version = GPFS_ACL_VERSION_NFS4;
	gpfs_acl->acl_type = GPFS_ACL_TYPE_NFS4;
	gpfs_acl->acl_nace = fsal_acl->naces;
	gpfs_acl->acl_len = offsetof(gpfs_acl_t, ace_v1) +
				gpfs_acl->acl_nace * sizeof(gpfs_ace_v4_t);

	for (ace = fsal_acl->aces, i = 0;
	     ace < (fsal_acl->aces + fsal_acl->naces); ace++, i++) {
		gpfs_acl->ace_v4[i].aceType = ace->type;
		gpfs_acl->ace_v4[i].aceFlags = ace->flag;
		gpfs_acl->ace_v4[i].aceIFlags = ace->iflag;
		gpfs_acl->ace_v4[i].aceMask = ace->perm;

		if (IS_FSAL_ACE_SPECIAL_ID(*ace)) {
			gpfs_acl->ace_v4[i].aceWho = ace->who.uid;
		} else {
			if (IS_FSAL_ACE_GROUP_ID(*ace))
				gpfs_acl->ace_v4[i].aceWho = ace->who.gid;
			else
				gpfs_acl->ace_v4[i].aceWho = ace->who.uid;
		}

		LogMidDebug(COMPONENT_FSAL,
			    "fsal_acl_2_gpfs_acl: gpfs ace: type = 0x%x, flag = 0x%x, perm = 0x%x, special = %d, %s = 0x%x",
			    ace->type, ace->flag, ace->perm,
			    (ace->iflag & FSAL_ACE_IFLAG_SPECIAL_ID) ? 1 : 0,
			    (ace->flag & FSAL_ACE_FLAG_GROUP_ID) ? "gid" :
								   "uid",
			    gpfs_acl->ace_v4[i].aceWho);

		/* It is invalid to set inherit flags on non dir objects */
		if (dir_hdl->type != DIRECTORY &&
		    (gpfs_acl->ace_v4[i].aceFlags & FSAL_ACE_FLAG_INHERIT)) {
			LogMidDebug(COMPONENT_FSAL,
			   "attempt to set inherit flag to non dir object");
			return fsalstat(ERR_FSAL_INVAL, 0);
		}

		/* It is invalid to set inherit only with
		 * out an actual inherit flag */
		if ((gpfs_acl->ace_v4[i].aceFlags & FSAL_ACE_FLAG_INHERIT) ==
			FSAL_ACE_FLAG_INHERIT_ONLY) {
			LogMidDebug(COMPONENT_FSAL,
			   "attempt to set inherit only without an inherit flag");
			return fsalstat(ERR_FSAL_INVAL, 0);
		}
	}

	return fsalstat(ERR_FSAL_NO_ERROR, 0);
}

