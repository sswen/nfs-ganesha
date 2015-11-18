/** @file  gpfs_main.h
 *  @brief GPFS FSAL module core (main) header
 *
 * Copyright (C) 2015 International Business Machines
 * All rights reserved.
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
 */

#include <config.h>
#include <fsal_api.h>
#include <fsal_types.h>

static const char myname[] = "GPFS";

/** @struct gpfs_fsal_module
 *  @brief GPFS FSAL module private storage
 */
struct gpfs_fsal_module {
	struct fsal_module fsal;
	struct fsal_staticfsinfo_t fs_info;
	/** gpfsfs_specific_initinfo_t specific_info;  placeholder */
};

/** @struct default_gpfs_info
 *  @brief filesystem info for GPFS
 */
static struct fsal_staticfsinfo_t default_gpfs_info = {
	.maxfilesize = UINT64_MAX,
	.maxlink = _POSIX_LINK_MAX,
	.maxnamelen = 1024,
	.maxpathlen = 1024,
	.no_trunc = true,
	.chown_restricted = false,
	.case_insensitive = false,
	.case_preserving = true,
	.link_support = true,
	.symlink_support = true,
	.lock_support = true,
	.lock_support_owner = true,
	.lock_support_async_block = true,
	.named_attr = true,
	.unique_handles = true,
	.lease_time = {10, 0},
	.acl_support = FSAL_ACLSUPPORT_ALLOW | FSAL_ACLSUPPORT_DENY,
	.cansettime = true,
	.homogenous = true,
	.supported_attrs = GPFS_SUPPORTED_ATTRIBUTES,
	.maxread = FSAL_MAXIOSIZE,
	.maxwrite = FSAL_MAXIOSIZE,
	.umask = 0,
	.auth_exportpath_xdev = true,
	.xattr_access_rights = 0,
	.share_support = true,
	.share_support_owner = false,
	.delegations = FSAL_OPTION_FILE_READ_DELEG, /** not working with pNFS */
	.pnfs_mds = true,
	.pnfs_ds = true,
	.fsal_trace = true,
	.reopen_method = true,
	.fsal_grace = false,
	.link_supports_permission_checks = true,
};

/** @struct gpfs_params
 *  @brief Configuration items
 */
static struct config_item gpfs_params[] = {
	CONF_ITEM_BOOL("link_support", true,
		       fsal_staticfsinfo_t, link_support),
	CONF_ITEM_BOOL("symlink_support", true,
		       fsal_staticfsinfo_t, symlink_support),
	CONF_ITEM_BOOL("cansettime", true,
		       fsal_staticfsinfo_t, cansettime),
	CONF_ITEM_MODE("umask", 0,
		       fsal_staticfsinfo_t, umask),
	CONF_ITEM_BOOL("auth_xdev_export", false,
		       fsal_staticfsinfo_t, auth_exportpath_xdev),
	CONF_ITEM_MODE("xattr_access_rights", 0400,
		       fsal_staticfsinfo_t, xattr_access_rights),
	/** At the moment GPFS doesn't support WRITE delegations */
	CONF_ITEM_ENUM_BITS("Delegations",
			    FSAL_OPTION_FILE_READ_DELEG,
			    FSAL_OPTION_FILE_DELEGATIONS,
			    deleg_types, fsal_staticfsinfo_t, delegations),
	CONF_ITEM_BOOL("PNFS_MDS", true,
		       fsal_staticfsinfo_t, pnfs_mds),
	CONF_ITEM_BOOL("PNFS_DS", true,
		       fsal_staticfsinfo_t, pnfs_ds),
	CONF_ITEM_BOOL("fsal_trace", true,
		       fsal_staticfsinfo_t, fsal_trace),
	CONF_ITEM_BOOL("fsal_grace", false,
		       fsal_staticfsinfo_t, fsal_grace),
	CONFIG_EOL
};

/** @struct gpfs_param
 *  @brief Configuration block
 */
static struct config_block gpfs_param = {
	.dbus_interface_name = "org.ganesha.nfsd.config.fsal.gpfs",
	.blk_desc.name = "GPFS",
	.blk_desc.type = CONFIG_BLOCK,
	.blk_desc.u.blk.init = noop_conf_init,
	.blk_desc.u.blk.params = gpfs_params,
	.blk_desc.u.blk.commit = noop_conf_commit
};

/** @struct GPFS
 *  @brief my module private storage
 */
static struct gpfs_fsal_module GPFS;

