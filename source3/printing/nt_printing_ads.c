/*
 *  Unix SMB/CIFS implementation.
 *  RPC Pipe client / server routines
 *  Copyright (C) Andrew Tridgell              1992-2000,
 *  Copyright (C) Jean François Micouleau      1998-2000.
 *  Copyright (C) Gerald Carter                2002-2005.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include "includes.h"
#include "../librpc/gen_ndr/spoolss.h"
#include "rpc_server/spoolss/srv_spoolss_util.h"
#include "nt_printing.h"
#include "ads.h"
#include "secrets.h"
#include "krb5_env.h"
#include "../libcli/registry/util_reg.h"
#include "auth.h"
#include "../librpc/ndr/libndr.h"
#include "rpc_client/cli_winreg_spoolss.h"

#ifdef HAVE_ADS
/*****************************************************************
 ****************************************************************/

WERROR nt_printer_guid_store(struct messaging_context *msg_ctx,
			     const char *printer, struct GUID guid)
{
	TALLOC_CTX *tmp_ctx;
	const struct auth_session_info *session_info;
	const char *guid_str;
	DATA_BLOB blob;
	WERROR result;

	tmp_ctx = talloc_new(NULL);
	if (!tmp_ctx) {
		DEBUG(0, ("Out of memory?!\n"));
		return WERR_NOT_ENOUGH_MEMORY;
	}

	session_info = get_session_info_system();
	if (session_info == NULL) {
		DEBUG(0, ("Could not get system session_info\n"));
		result = WERR_NOT_ENOUGH_MEMORY;
		goto done;
	}

	guid_str = GUID_string(tmp_ctx, &guid);
	if (!guid_str) {
		DEBUG(0, ("Out of memory?!\n"));
		result = WERR_NOT_ENOUGH_MEMORY;
		goto done;
	}

	/* We used to store this as a REG_BINARY but that causes
	   Vista to whine */

	if (!push_reg_sz(tmp_ctx, &blob, guid_str)) {
		DEBUG(0, ("Could not marshall string %s for objectGUID\n",
			  guid_str));
		result = WERR_NOT_ENOUGH_MEMORY;
		goto done;
	}

	result = winreg_set_printer_dataex_internal(tmp_ctx, session_info, msg_ctx,
					   printer,
					   SPOOL_DSSPOOLER_KEY, "objectGUID",
					   REG_SZ, blob.data, blob.length);
	if (!W_ERROR_IS_OK(result)) {
		DEBUG(0, ("Failed to store GUID for printer %s\n", printer));
		goto done;
	}

	result = WERR_OK;
done:
	talloc_free(tmp_ctx);

	return result;
}

static WERROR nt_printer_dn_lookup(TALLOC_CTX *mem_ctx,
				   ADS_STRUCT *ads,
				   const char *printer,
				   char **pprinter_dn)
{
	char *printer_dn = NULL;
	char *srv_dn = NULL;
	char *srv_cn_0 = NULL;
	char *srv_cn_escaped = NULL;
	char *sharename_escaped = NULL;
	char *srv_dn_utf8 = NULL;
	char **srv_cn_utf8 = NULL;
	size_t converted_size;
	ADS_STATUS ads_status;
	LDAPMessage *res;
	WERROR result;
	bool ok;

	ads_status = ads_find_machine_acct(ads, &res, lp_netbios_name());
	if (!ADS_ERR_OK(ads_status)) {
		DEBUG(2, ("Failed to find machine account for %s\n",
			  lp_netbios_name()));
		result = WERR_NOT_FOUND;
		goto err_out;
	}

	/*
	 * We use ldap_get_dn here as we need the answer in utf8 to call
	 * ldap_explode_dn(). JRA.
	 */
	srv_dn_utf8 = ldap_get_dn((LDAP *)ads->ldap.ld, (LDAPMessage *)res);
	ads_msgfree(ads, res);
	if (srv_dn_utf8 == NULL) {
		result = WERR_RPC_S_SERVER_UNAVAILABLE;
		goto err_out;
	}

	srv_cn_utf8 = ldap_explode_dn(srv_dn_utf8, 1);
	if (srv_cn_utf8 == NULL) {
		ldap_memfree(srv_dn_utf8);
		result = WERR_RPC_S_SERVER_UNAVAILABLE;
		goto err_out;
	}

	/* Now convert to CH_UNIX. */
	ok = pull_utf8_talloc(mem_ctx, &srv_dn, srv_dn_utf8, &converted_size);
	ldap_memfree(srv_dn_utf8);
	if (!ok) {
		ldap_memfree(srv_cn_utf8);
		result = WERR_RPC_S_SERVER_UNAVAILABLE;
		goto err_out;
	}

	ok = pull_utf8_talloc(mem_ctx, &srv_cn_0, srv_cn_utf8[0], &converted_size);
	ldap_memfree(srv_cn_utf8);
	if (!ok) {
		result = WERR_RPC_S_SERVER_UNAVAILABLE;
		goto err_out;
	}

	srv_cn_escaped = escape_rdn_val_string_alloc(srv_cn_0);
	if (srv_cn_escaped == NULL) {
		result = WERR_RPC_S_SERVER_UNAVAILABLE;
		goto err_out;
	}

	sharename_escaped = escape_rdn_val_string_alloc(printer);
	if (sharename_escaped == NULL) {
		result = WERR_RPC_S_SERVER_UNAVAILABLE;
		goto err_out;
	}

	printer_dn = talloc_asprintf(mem_ctx,
				     "cn=%s-%s,%s",
				     srv_cn_escaped,
				     sharename_escaped,
				     srv_dn);
	if (printer_dn == NULL) {
		result = WERR_NOT_ENOUGH_MEMORY;
		goto err_out;
	}

	*pprinter_dn = printer_dn;

	result = WERR_OK;
err_out:
	SAFE_FREE(sharename_escaped);
	SAFE_FREE(srv_cn_escaped);
	TALLOC_FREE(srv_cn_0);
	TALLOC_FREE(srv_dn);
	return result;
}

static WERROR nt_printer_guid_retrieve_internal(ADS_STRUCT *ads,
						const char *printer_dn,
						struct GUID *pguid)
{
	ADS_STATUS ads_status;
	LDAPMessage *res;
	const char *attrs[] = {"objectGUID", NULL};
	struct GUID guid;
	bool ok;

	ads_status = ads_search_dn(ads, &res, printer_dn, attrs);
	if (!ADS_ERR_OK(ads_status)) {
		DEBUG(2, ("Failed to retrieve GUID from DC - %s\n",
			  ads_errstr(ads_status)));
		return WERR_FILE_NOT_FOUND;
	}

	ZERO_STRUCT(guid);
	ok = ads_pull_guid(ads, res, &guid);
	ads_msgfree(ads, res);
	if (!ok) {
		return WERR_NOT_ENOUGH_MEMORY;
	}

	*pguid = guid;

	return WERR_OK;
}

WERROR nt_printer_guid_retrieve(TALLOC_CTX *mem_ctx, const char *printer,
				struct GUID *pguid)
{
	ADS_STRUCT *ads = NULL;
	char *old_krb5ccname = NULL;
	char *printer_dn;
	WERROR result;
	ADS_STATUS ads_status;
	TALLOC_CTX *tmp_ctx = talloc_stackframe();
	char *machine_password = NULL;

	ads = ads_init(tmp_ctx,
		       lp_realm(),
		       lp_workgroup(),
		       NULL,
		       ADS_SASL_PLAIN);
	if (ads == NULL) {
		result = WERR_RPC_S_SERVER_UNAVAILABLE;
		goto out;
	}

	old_krb5ccname = getenv(KRB5_ENV_CCNAME);
	setenv(KRB5_ENV_CCNAME, "MEMORY:prtpub_cache", 1);
	ADS_TALLOC_CONST_FREE(ads->auth.password);
	machine_password = secrets_fetch_machine_password(lp_workgroup(),
							    NULL, NULL);
	if (machine_password != NULL) {
		ads->auth.password = talloc_strdup(ads, machine_password);
		SAFE_FREE(machine_password);
		if (ads->auth.password == NULL) {
			result = WERR_NOT_ENOUGH_MEMORY;
			goto out;
		}
	}

	ads_status = ads_connect(ads);
	if (!ADS_ERR_OK(ads_status)) {
		DEBUG(3, ("ads_connect failed: %s\n", ads_errstr(ads_status)));
		result = WERR_ACCESS_DENIED;
		goto out;
	}

	result = nt_printer_dn_lookup(tmp_ctx, ads, printer, &printer_dn);
	if (!W_ERROR_IS_OK(result)) {
		goto out;
	}

	result = nt_printer_guid_retrieve_internal(ads, printer_dn, pguid);
out:
	TALLOC_FREE(tmp_ctx);
	ads_kdestroy("MEMORY:prtpub_cache");
	unsetenv(KRB5_ENV_CCNAME);
	if (old_krb5ccname != NULL) {
		setenv(KRB5_ENV_CCNAME, old_krb5ccname, 0);
	}

	return result;
}

WERROR nt_printer_guid_get(TALLOC_CTX *mem_ctx,
			   const struct auth_session_info *session_info,
			   struct messaging_context *msg_ctx,
			   const char *printer, struct GUID *guid)
{
	TALLOC_CTX *tmp_ctx;
	enum winreg_Type type;
	DATA_BLOB blob;
	uint32_t len;
	NTSTATUS status;
	WERROR result;

	tmp_ctx = talloc_new(mem_ctx);
	if (tmp_ctx == NULL) {
		DEBUG(0, ("out of memory?!\n"));
		return WERR_NOT_ENOUGH_MEMORY;
	}

	result = winreg_get_printer_dataex_internal(tmp_ctx, session_info,
						    msg_ctx, printer,
						    SPOOL_DSSPOOLER_KEY,
						    "objectGUID",
						    &type,
						    &blob.data,
						    &len);
	if (!W_ERROR_IS_OK(result)) {
		DEBUG(0, ("Failed to get GUID for printer %s\n", printer));
		goto out_ctx_free;
	}
	blob.length = (size_t)len;

	/* We used to store the guid as REG_BINARY, then swapped
	   to REG_SZ for Vista compatibility so check for both */

	switch (type) {
	case REG_SZ: {
		bool ok;
		const char *guid_str;
		ok = pull_reg_sz(tmp_ctx, &blob, &guid_str);
		if (!ok) {
			DEBUG(0, ("Failed to unmarshall GUID for printer %s\n",
				  printer));
			result = WERR_REGISTRY_CORRUPT;
			goto out_ctx_free;
		}
		status = GUID_from_string(guid_str, guid);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(0, ("bad GUID for printer %s\n", printer));
			result = ntstatus_to_werror(status);
			goto out_ctx_free;
		}
		break;
	}
	case REG_BINARY:
		if (blob.length != sizeof(struct GUID)) {
			DEBUG(0, ("bad GUID for printer %s\n", printer));
			result = WERR_REGISTRY_CORRUPT;
			goto out_ctx_free;
		}
		memcpy(guid, blob.data, sizeof(struct GUID));
		break;
	default:
		DEBUG(0,("GUID value stored as invalid type (%d)\n", type));
		result = WERR_REGISTRY_CORRUPT;
		goto out_ctx_free;
		break;
	}
	result = WERR_OK;

out_ctx_free:
	talloc_free(tmp_ctx);
	return result;
}

static WERROR nt_printer_devmode_to_mods(TALLOC_CTX *ctx,
					struct spoolss_DeviceMode *devmode,
					ADS_MODLIST *mods)
{
	char *str = NULL;
	ADS_STATUS status;

	/*
	   the device mode fields bits allow us to make an educated guess if a
	   printer feature is supported. For sure a feature must be unsupported if
	   the fields bit is not set. Device Mode Extra Data and FeatureOptionPairs
	   might help to figure out more information here. Common attributes, that
	   we can't handle yet:
		SPOOL_REG_PRINTBINNAMES - printBinNames
		SPOOL_REG_PRINTMAXXEXTENT - printMaxXExtent
		SPOOL_REG_PRINTMAXYEXTENT - printMaxYExtent
		SPOOL_REG_PRINTMINXEXTENT - printMinXExtent
		SPOOL_REG_PRINTMINYEXTENT - printMinYExtent
		SPOOL_REG_PRINTSTAPLINGSUPPORTED - printStaplingSupported
		SPOOL_REG_PRINTPAGESPERMINUTE - printPagesPerMinute
		SPOOL_REG_PRINTRATE - printRate
		SPOOL_REG_PRINTRATEUNIT - printRateUnit
		SPOOL_REG_PRINTMEDIAREADY - printMediaReady
		SPOOL_REG_PRINTMEDIASUPPORTED - printMediaSupported
		SPOOL_REG_PRINTNUMBERUP - printNumberUp
		SPOOL_REG_PRINTMAXCOPIES - printMaxCopies
	*/
	if (devmode->fields & DEVMODE_COLOR) {
		status = ads_mod_str(ctx, mods, SPOOL_REG_PRINTCOLOR, "TRUE");
	} else {
		status = ads_mod_str(ctx, mods, SPOOL_REG_PRINTCOLOR, "FALSE");
	}
	if (!ADS_ERR_OK(status)) {
		return WERR_NOT_ENOUGH_MEMORY;
	}

	if (devmode->fields & DEVMODE_DUPLEX) {
		status = ads_mod_str(ctx, mods, SPOOL_REG_PRINTDUPLEXSUPPORTED, "TRUE");
	} else {
		status = ads_mod_str(ctx, mods, SPOOL_REG_PRINTDUPLEXSUPPORTED, "FALSE");
	}
	if (!ADS_ERR_OK(status)) {
		return WERR_NOT_ENOUGH_MEMORY;
	}

	if (devmode->fields & DEVMODE_COLLATE) {
		status = ads_mod_str(ctx, mods, SPOOL_REG_PRINTCOLLATE, "TRUE");
	} else {
		status = ads_mod_str(ctx, mods, SPOOL_REG_PRINTCOLLATE, "FALSE");
	}
	if (!ADS_ERR_OK(status)) {
		return WERR_NOT_ENOUGH_MEMORY;
	}

	/* portrait mode is always supported, LANDSCAPE is optional */
	status = ads_mod_str(ctx, mods, SPOOL_REG_PRINTORIENTATIONSSUPPORTED, "PORTRAIT");
	if (!ADS_ERR_OK(status)) {
		return WERR_NOT_ENOUGH_MEMORY;
	}
	if (devmode->fields & DEVMODE_ORIENTATION) {
		status = ads_mod_str(ctx, mods, SPOOL_REG_PRINTORIENTATIONSSUPPORTED, "LANDSCAPE");
		if (!ADS_ERR_OK(status)) {
			return WERR_NOT_ENOUGH_MEMORY;
		}
	}

	/* the driverVersion attribute in AD contains actually specversion */
	str = talloc_asprintf(ctx, "%u", devmode->specversion);
	if (str == NULL) {
		return WERR_NOT_ENOUGH_MEMORY;
	}
	if (strlen(str) != 0) {
		status = ads_mod_str(ctx, mods, SPOOL_REG_DRIVERVERSION, str);
		if (!ADS_ERR_OK(status)) {
			return WERR_NOT_ENOUGH_MEMORY;
		}
	}

	/* devmode->yresolution is a good candidate for printMaxResolutionSupported */
	str = talloc_asprintf(ctx, "%u", devmode->yresolution);
	if (str == NULL) {
		return WERR_NOT_ENOUGH_MEMORY;
	}
	if (strlen(str) != 0) {
		status = ads_mod_str(ctx, mods, SPOOL_REG_PRINTMAXRESOLUTIONSUPPORTED, str);
		if (!ADS_ERR_OK(status)) {
			return WERR_NOT_ENOUGH_MEMORY;
		}
	}

	return WERR_OK;
}



static WERROR nt_printer_info_to_mods(TALLOC_CTX *ctx,
				      struct spoolss_PrinterInfo2 *info2,
				      ADS_MODLIST *mods)
{
	char *info_str;

	ads_mod_str(ctx, mods, SPOOL_REG_PRINTERNAME, info2->sharename);
	ads_mod_str(ctx, mods, SPOOL_REG_PRINTSHARENAME, info2->sharename);
	ads_mod_str(ctx, mods, SPOOL_REG_SHORTSERVERNAME, lp_netbios_name());
	ads_mod_str(ctx, mods, SPOOL_REG_SERVERNAME, get_mydnsfullname());

	info_str = talloc_asprintf(ctx, "\\\\%s\\%s",
				   get_mydnsfullname(), info2->sharename);
	if (info_str == NULL) {
		return WERR_NOT_ENOUGH_MEMORY;
	}
	ads_mod_str(ctx, mods, SPOOL_REG_UNCNAME, info_str);

	info_str = talloc_asprintf(ctx, "%d", 4);
	if (info_str == NULL) {
		return WERR_NOT_ENOUGH_MEMORY;
	}
	ads_mod_str(ctx, mods, SPOOL_REG_VERSIONNUMBER, info_str);

	/* empty strings in the mods list result in an attrubute error */
	if (strlen(info2->drivername) != 0)
		ads_mod_str(ctx, mods, SPOOL_REG_DRIVERNAME, info2->drivername);
	if (strlen(info2->location) != 0)
		ads_mod_str(ctx, mods, SPOOL_REG_LOCATION, info2->location);
	if (strlen(info2->comment) != 0)
		ads_mod_str(ctx, mods, SPOOL_REG_DESCRIPTION, info2->comment);
	if (strlen(info2->portname) != 0)
		ads_mod_str(ctx, mods, SPOOL_REG_PORTNAME, info2->portname);
	if (strlen(info2->sepfile) != 0)
		ads_mod_str(ctx, mods, SPOOL_REG_PRINTSEPARATORFILE, info2->sepfile);

	info_str = talloc_asprintf(ctx, "%u", info2->starttime);
	if (info_str == NULL) {
		return WERR_NOT_ENOUGH_MEMORY;
	}
	ads_mod_str(ctx, mods, SPOOL_REG_PRINTSTARTTIME, info_str);

	info_str = talloc_asprintf(ctx, "%u", info2->untiltime);
	if (info_str == NULL) {
		return WERR_NOT_ENOUGH_MEMORY;
	}
	ads_mod_str(ctx, mods, SPOOL_REG_PRINTENDTIME, info_str);

	info_str = talloc_asprintf(ctx, "%u", info2->priority);
	if (info_str == NULL) {
		return WERR_NOT_ENOUGH_MEMORY;
	}
	ads_mod_str(ctx, mods, SPOOL_REG_PRIORITY, info_str);

	if (info2->attributes & PRINTER_ATTRIBUTE_KEEPPRINTEDJOBS) {
		ads_mod_str(ctx, mods, SPOOL_REG_PRINTKEEPPRINTEDJOBS, "TRUE");
	} else {
		ads_mod_str(ctx, mods, SPOOL_REG_PRINTKEEPPRINTEDJOBS, "FALSE");
	}

	switch (info2->attributes & 0x3) {
	case 0:
		ads_mod_str(ctx, mods, SPOOL_REG_PRINTSPOOLING,
			    SPOOL_REGVAL_PRINTWHILESPOOLING);
		break;
	case 1:
		ads_mod_str(ctx, mods, SPOOL_REG_PRINTSPOOLING,
			    SPOOL_REGVAL_PRINTAFTERSPOOLED);
		break;
	case 2:
		ads_mod_str(ctx, mods, SPOOL_REG_PRINTSPOOLING,
			    SPOOL_REGVAL_PRINTDIRECT);
		break;
	default:
		DEBUG(3, ("unsupported printer attributes %x\n",
			  info2->attributes));
	}

	if (info2->devmode != NULL) {
		WERROR werr;
		werr = nt_printer_devmode_to_mods(ctx, info2->devmode, mods);
		if (!W_ERROR_IS_OK(werr)) {
			return werr;
		}
	}

	return WERR_OK;
}

static WERROR nt_printer_publish_ads(struct messaging_context *msg_ctx,
				     ADS_STRUCT *ads,
				     struct spoolss_PrinterInfo2 *pinfo2)
{
	ADS_STATUS ads_rc;
	TALLOC_CTX *ctx = talloc_stackframe();
	ADS_MODLIST mods;
	struct GUID guid;
	WERROR win_rc = WERR_OK;
	const char *printer = pinfo2->sharename;
	char *printer_dn = NULL;

	/* build the ads mods */
	DEBUG(5, ("publishing printer %s\n", printer));

	win_rc = nt_printer_dn_lookup(ctx, ads, printer, &printer_dn);
	if (!W_ERROR_IS_OK(win_rc)) {
		DEBUG(2, ("Failed to create printer dn\n"));
		TALLOC_FREE(ctx);
		return win_rc;
	}

	mods = ads_init_mods(ctx);

	if (mods == NULL) {
		TALLOC_FREE(ctx);
		return WERR_NOT_ENOUGH_MEMORY;
	}

	win_rc = nt_printer_info_to_mods(ctx, pinfo2, &mods);
	if (!W_ERROR_IS_OK(win_rc)) {
		TALLOC_FREE(ctx);
		return win_rc;
	}

	/* publish it */
	ads_rc = ads_mod_printer_entry(ads, printer_dn, ctx, &mods);
	if (ads_rc.err.rc == LDAP_NO_SUCH_OBJECT) {
		int i;
		for (i=0; mods[i] != 0; i++)
			;
		mods[i] = (LDAPMod *)-1;
		ads_rc = ads_add_printer_entry(ads, printer_dn, ctx, &mods);
	}

	if (!ADS_ERR_OK(ads_rc)) {
		DEBUG(3, ("error publishing %s: %s\n",
			  printer, ads_errstr(ads_rc)));
		/* XXX failed to publish, so no guid to retrieve */
	}

	win_rc = nt_printer_guid_retrieve_internal(ads, printer_dn, &guid);
	if (!W_ERROR_IS_OK(win_rc)) {
		TALLOC_FREE(ctx);
		return win_rc;
	}

	win_rc = nt_printer_guid_store(msg_ctx, printer, guid);
	if (!W_ERROR_IS_OK(win_rc)) {
		DEBUG(3, ("failed to store printer %s guid\n",
			  printer));
		/* not catastrophic, retrieve on next use */
		win_rc = WERR_OK;
	}

	TALLOC_FREE(ctx);

	return win_rc;
}

static WERROR nt_printer_unpublish_ads(ADS_STRUCT *ads,
                                       const char *printer)
{
	ADS_STATUS ads_rc;
	LDAPMessage *res = NULL;
	char *prt_dn = NULL;

	DEBUG(5, ("unpublishing printer %s\n", printer));

	/* remove the printer from the directory */
	ads_rc = ads_find_printer_on_server(ads, &res,
					    printer, lp_netbios_name());

	if (ADS_ERR_OK(ads_rc) && res && ads_count_replies(ads, res)) {
		prt_dn = ads_get_dn(ads, talloc_tos(), res);
		if (!prt_dn) {
			ads_msgfree(ads, res);
			return WERR_NOT_ENOUGH_MEMORY;
		}
		ads_rc = ads_del_dn(ads, prt_dn);
		TALLOC_FREE(prt_dn);
	}

	if (res) {
		ads_msgfree(ads, res);
	}
	return WERR_OK;
}

/****************************************************************************
 * Publish a printer in the directory
 *
 * @param mem_ctx      memory context
 * @param session_info  session_info to access winreg pipe
 * @param pinfo2       printer information
 * @param action       publish/unpublish action
 * @return WERROR indicating status of publishing
 ***************************************************************************/

WERROR nt_printer_publish(TALLOC_CTX *mem_ctx,
			  const struct auth_session_info *session_info,
			  struct messaging_context *msg_ctx,
			  struct spoolss_PrinterInfo2 *pinfo2,
			  int action)
{
	TALLOC_CTX *tmp_ctx = talloc_stackframe();
	uint32_t info2_mask = SPOOLSS_PRINTER_INFO_ATTRIBUTES;
	struct spoolss_SetPrinterInfo2 *sinfo2;
	ADS_STATUS ads_rc;
	ADS_STRUCT *ads = NULL;
	WERROR win_rc;
	char *old_krb5ccname = NULL;
	char *machine_password = NULL;

	sinfo2 = talloc_zero(tmp_ctx, struct spoolss_SetPrinterInfo2);
	if (!sinfo2) {
		win_rc = WERR_NOT_ENOUGH_MEMORY;
		goto done;
	}

	switch (action) {
	case DSPRINT_PUBLISH:
	case DSPRINT_UPDATE:
		pinfo2->attributes |= PRINTER_ATTRIBUTE_PUBLISHED;
		break;
	case DSPRINT_UNPUBLISH:
		pinfo2->attributes &= (~PRINTER_ATTRIBUTE_PUBLISHED);
		break;
	default:
		win_rc = WERR_NOT_SUPPORTED;
		goto done;
	}

	sinfo2->attributes = pinfo2->attributes;

	win_rc = winreg_update_printer_internal(tmp_ctx, session_info, msg_ctx,
					pinfo2->sharename, info2_mask,
					sinfo2, NULL, NULL);
	if (!W_ERROR_IS_OK(win_rc)) {
		DBG_NOTICE("Failed to update data for printer [%s] - %s\n",
			   pinfo2->sharename,
			   win_errstr(win_rc));
		goto done;
	}

	TALLOC_FREE(sinfo2);

	ads = ads_init(tmp_ctx,
		       lp_realm(),
		       lp_workgroup(),
		       NULL,
		       ADS_SASL_PLAIN);
	if (!ads) {
		DEBUG(3, ("ads_init() failed\n"));
		win_rc = WERR_RPC_S_SERVER_UNAVAILABLE;
		goto done;
	}
	old_krb5ccname = getenv(KRB5_ENV_CCNAME);
	setenv(KRB5_ENV_CCNAME, "MEMORY:prtpub_cache", 1);
	ADS_TALLOC_CONST_FREE(ads->auth.password);
	machine_password = secrets_fetch_machine_password(lp_workgroup(),
		NULL, NULL);
	if (machine_password != NULL) {
		ads->auth.password = talloc_strdup(ads, machine_password);
		SAFE_FREE(machine_password);
		if (ads->auth.password == NULL) {
			win_rc = WERR_NOT_ENOUGH_MEMORY;
			goto done;
		}
	}

	/* ads_connect() will find the DC for us */
	ads_rc = ads_connect(ads);
	if (!ADS_ERR_OK(ads_rc)) {
		DEBUG(3, ("ads_connect failed: %s\n", ads_errstr(ads_rc)));
		win_rc = WERR_ACCESS_DENIED;
		goto done;
	}

	switch (action) {
	case DSPRINT_PUBLISH:
	case DSPRINT_UPDATE:
		win_rc = nt_printer_publish_ads(msg_ctx, ads, pinfo2);
		break;
	case DSPRINT_UNPUBLISH:
		win_rc = nt_printer_unpublish_ads(ads, pinfo2->sharename);
		break;
	}

done:
	ads_kdestroy("MEMORY:prtpub_cache");
	unsetenv(KRB5_ENV_CCNAME);
	if (old_krb5ccname) {
		setenv(KRB5_ENV_CCNAME, old_krb5ccname, 0);
	}

	TALLOC_FREE(tmp_ctx);

	return win_rc;
}

WERROR check_published_printers(struct messaging_context *msg_ctx)
{
	const struct loadparm_substitution *lp_sub =
		loadparm_s3_global_substitution();
	ADS_STATUS ads_rc;
	ADS_STRUCT *ads = NULL;
	int snum;
	int n_services = lp_numservices();
	TALLOC_CTX *tmp_ctx = talloc_stackframe();
	struct auth_session_info *session_info = NULL;
	struct spoolss_PrinterInfo2 *pinfo2;
	NTSTATUS status;
	WERROR result;
	char *old_krb5ccname = NULL;
	char *machine_password = NULL;

	ads = ads_init(tmp_ctx,
		       lp_realm(),
		       lp_workgroup(),
		       NULL,
		       ADS_SASL_PLAIN);
	if (!ads) {
		DEBUG(3, ("ads_init() failed\n"));
		TALLOC_FREE(tmp_ctx);
		return WERR_RPC_S_SERVER_UNAVAILABLE;
	}
	old_krb5ccname = getenv(KRB5_ENV_CCNAME);
	setenv(KRB5_ENV_CCNAME, "MEMORY:prtpub_cache", 1);
	ADS_TALLOC_CONST_FREE(ads->auth.password);
	machine_password = secrets_fetch_machine_password(lp_workgroup(),
		NULL, NULL);
	if (machine_password != NULL) {
		ads->auth.password = talloc_strdup(ads, machine_password);
		SAFE_FREE(machine_password);
		if (ads->auth.password == NULL) {
			result = WERR_NOT_ENOUGH_MEMORY;
			goto done;
		}
	}
	/* ads_connect() will find the DC for us */
	ads_rc = ads_connect(ads);
	if (!ADS_ERR_OK(ads_rc)) {
		DEBUG(3, ("ads_connect failed: %s\n", ads_errstr(ads_rc)));
		result = WERR_ACCESS_DENIED;
		goto done;
	}

	status = make_session_info_system(tmp_ctx, &session_info);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("check_published_printers: "
			  "Could not create system session_info\n"));
		result = WERR_ACCESS_DENIED;
		goto done;
	}

	for (snum = 0; snum < n_services; snum++) {
		if (!lp_snum_ok(snum) || !lp_printable(snum)) {
			continue;
		}

		result = winreg_get_printer_internal(tmp_ctx, session_info, msg_ctx,
					    lp_servicename(talloc_tos(), lp_sub, snum),
					    &pinfo2);
		if (!W_ERROR_IS_OK(result)) {
			continue;
		}

		if (pinfo2->attributes & PRINTER_ATTRIBUTE_PUBLISHED) {
			nt_printer_publish_ads(msg_ctx, ads, pinfo2);
		}

		TALLOC_FREE(pinfo2);
	}

	result = WERR_OK;
done:
	ads_kdestroy("MEMORY:prtpub_cache");
	unsetenv(KRB5_ENV_CCNAME);
	if (old_krb5ccname) {
		setenv(KRB5_ENV_CCNAME, old_krb5ccname, 0);
	}
	talloc_free(tmp_ctx);
	return result;
}

bool is_printer_published(TALLOC_CTX *mem_ctx,
			  const struct auth_session_info *session_info,
			  struct messaging_context *msg_ctx,
			  const char *servername,
			  const char *printer,
			  struct spoolss_PrinterInfo2 **info2)
{
	struct spoolss_PrinterInfo2 *pinfo2 = NULL;
	WERROR result;
	struct dcerpc_binding_handle *b;

	result = winreg_printer_binding_handle(mem_ctx,
					       session_info,
					       msg_ctx,
					       &b);
	if (!W_ERROR_IS_OK(result)) {
		return false;
	}

	result = winreg_get_printer(mem_ctx, b,
				    printer, &pinfo2);
	if (!W_ERROR_IS_OK(result)) {
		return false;
	}

	if (!(pinfo2->attributes & PRINTER_ATTRIBUTE_PUBLISHED)) {
		TALLOC_FREE(pinfo2);
		return false;
	}

	if (info2) {
		*info2 = talloc_move(mem_ctx, &pinfo2);
	}
	talloc_free(pinfo2);
	return true;
}
#else
WERROR nt_printer_guid_store(struct messaging_context *msg_ctx,
			   const char *printer, struct GUID guid)
{
	return WERR_NOT_SUPPORTED;
}

WERROR nt_printer_guid_retrieve(TALLOC_CTX *mem_ctx, const char *printer,
				struct GUID *pguid)
{
	return WERR_NOT_SUPPORTED;
}

WERROR nt_printer_guid_get(TALLOC_CTX *mem_ctx,
			   const struct auth_session_info *session_info,
			   struct messaging_context *msg_ctx,
			   const char *printer, struct GUID *guid)
{
	return WERR_NOT_SUPPORTED;
}

WERROR nt_printer_publish(TALLOC_CTX *mem_ctx,
			  const struct auth_session_info *session_info,
			  struct messaging_context *msg_ctx,
			  struct spoolss_PrinterInfo2 *pinfo2,
			  int action)
{
	return WERR_OK;
}

WERROR check_published_printers(struct messaging_context *msg_ctx)
{
	return WERR_OK;
}

bool is_printer_published(TALLOC_CTX *mem_ctx,
			  const struct auth_session_info *session_info,
			  struct messaging_context *msg_ctx,
			  const char *servername,
			  const char *printer,
			  struct spoolss_PrinterInfo2 **info2)
{
	return False;
}
#endif /* HAVE_ADS */
