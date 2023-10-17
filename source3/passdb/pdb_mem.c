/*
 * Unix SMB/CIFS implementation. 
 * SMB parameters and setup
 * Copyright (C) Andrew Tridgell       1992-1998 
 * Modified by Jeremy Allison          1995.
 * Modified by Gerald (Jerry) Carter   2000-2001,2003
 * Modified by Andrew Bartlett         2002.
 * 
 * This program is free software; you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 3 of the License, or (at your option)
 * any later version.
 * 
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 * 
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include "includes.h"
#include "passdb.h"
#include "system/passwd.h"
#include "system/filesys.h"
#include "../librpc/gen_ndr/samr.h"
#include "../libcli/security/security.h"
#include "passdb/pdb_mem.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_PASSDB

/* 
   smb_account is analogous to sam_passwd used everywhere
   else.  However, smb_account is limited to the information
   stored in memory 
 */

struct smb_account
{
	uint32_t smb_userid;      /* this is actually the unix uid_t */
	const char *smb_name;     /* username string */

	DATA_BLOB smb_lm_passwd;
	DATA_BLOB smb_nt_passwd;

	uint16_t acct_ctrl;             /* account info (ACB_xxxx bit-mask) */
	time_t pass_last_set_time;      /* password last set time */

	struct smb_account *next;
};

struct memory_privates
{
	struct smb_account *pwd;
};

/*********************************************************************
 Create a smb_account struct from a struct samu.
 We will not allocate any new memory.  The smb_account struct
 should only stay around as long as the struct samu does.
 ********************************************************************/

static bool build_smb_account(struct smb_account *smb_acc, const struct samu *sam_acc)
{
	uint32_t rid;

	if (sam_acc == NULL) 
		return False;
	ZERO_STRUCTP(smb_acc);

	if (!IS_SAM_DEFAULT(sam_acc, PDB_USERSID)) {
		rid = pdb_get_user_rid(sam_acc);

		/* If the user specified a RID, make sure its able to be both stored and retreived */
		if (rid == DOMAIN_RID_GUEST) {
			struct passwd *passwd = Get_Pwnam_alloc(NULL, lp_guest_account());
			if (!passwd) {
				DEBUG(0, ("Could not find guest account via Get_Pwnam_alloc()! (%s)\n", lp_guest_account()));
				return False;
			}
			smb_acc->smb_userid=passwd->pw_uid;
			TALLOC_FREE(passwd);
		} else if (algorithmic_pdb_rid_is_user(rid)) {
			smb_acc->smb_userid=algorithmic_pdb_user_rid_to_uid(rid);
		} else {
			DEBUG(0,("build_sam_pass: Failing attempt to store user with non-uid based user RID. \n"));
			return False;
		}
	}


	smb_acc->smb_name=(const char*)talloc_strdup(smb_acc, (const char*)pdb_get_username(sam_acc));

	size_t length = sam_acc->lm_pw.length;
	smb_acc->smb_lm_passwd.data = talloc_memdup(smb_acc, sam_acc->lm_pw.data, length);
	smb_acc->smb_lm_passwd.length = length;
	
	length = sam_acc->nt_pw.length;
	smb_acc->smb_nt_passwd.data = talloc_memdup(smb_acc, sam_acc->nt_pw.data, length);
	smb_acc->smb_nt_passwd.length = length;

	smb_acc->acct_ctrl=pdb_get_acct_ctrl(sam_acc);
	smb_acc->pass_last_set_time=pdb_get_pass_last_set_time(sam_acc);

	return True;
}	

/*********************************************************************
 Create a struct samu from a smb_account struct
 ********************************************************************/

static bool build_sam_account(struct samu *sam_acc, const struct smb_account *smb_acc)
{
	struct passwd *pwfile;

	if ( !sam_acc ) {
		DEBUG(5,("build_sam_account: struct samu is NULL\n"));
		return False;
	}

	/* verify the user account exists */
	if ( !(pwfile = Get_Pwnam_alloc(NULL, smb_acc->smb_name )) ) {
		DEBUG(0,("build_sam_account: Get_Pwnam_alloc failed!\n"));
		return False;
	}

	if ( !NT_STATUS_IS_OK( samu_set_unix(sam_acc, pwfile )) )
		return False;

	TALLOC_FREE(pwfile);

	/* set remaining fields */

	if (!pdb_set_nt_passwd (sam_acc, smb_acc->smb_nt_passwd.data, PDB_SET))
		return False;
	if (!pdb_set_lanman_passwd (sam_acc, smb_acc->smb_lm_passwd.data, PDB_SET))
		return False;
	pdb_set_acct_ctrl (sam_acc, smb_acc->acct_ctrl, PDB_SET);
	pdb_set_pass_last_set_time (sam_acc, smb_acc->pass_last_set_time, PDB_SET);
	pdb_set_pass_can_change_time (sam_acc, smb_acc->pass_last_set_time, PDB_SET);

	return True;
}

/*****************************************************************
 Functions to be implemented by the new passdb API 
 ****************************************************************/

static NTSTATUS memory_getsampwnam(struct pdb_methods *my_methods, struct samu *sam_acc, const char *username)
{
	struct memory_privates *data = (struct memory_privates*)my_methods->private_data;

	DEBUG(10, ("getsampwnam (memory): search by name: %s\n", username));

	struct smb_account *smb_pw = data->pwd;
	for (; smb_pw != NULL; smb_pw = smb_pw->next) {
		if (strequal(smb_pw->smb_name, username)) {
			break;
		}
	}

	/* did we locate the username in memory  */
	if (smb_pw == NULL) {
		return NT_STATUS_UNSUCCESSFUL;
	}

	DEBUG(10, ("getsampwnam (memory): found by name: %s\n", smb_pw->smb_name));

	if (!sam_acc) {
		DEBUG(10,("getsampwnam (memory): struct samu is NULL\n"));
		return NT_STATUS_UNSUCCESSFUL;
	}

	/* now build the struct samu */
	if (!build_sam_account(sam_acc, smb_pw))
		return NT_STATUS_UNSUCCESSFUL;

	/* success */
	return NT_STATUS_OK;
}

static NTSTATUS memory_getsampwsid(struct pdb_methods *my_methods, struct samu *sam_acc, const struct dom_sid *sid)
{
	uint32_t rid;
	struct dom_sid_buf buf;
	DEBUG(10, ("memory_getsampwrid: search by sid: %s\n", dom_sid_str_buf(sid, &buf)));

	if (!sid_peek_check_rid(get_global_sam_sid(), sid, &rid)) {
		return NT_STATUS_UNSUCCESSFUL;
	}

	/* More special case 'guest account' hacks... */
	if (rid == DOMAIN_RID_GUEST) {
		const char *guest_account = lp_guest_account();
		if (!(guest_account && *guest_account)) {
			DEBUG(1, ("Guest account not specified!\n"));
			return NT_STATUS_UNSUCCESSFUL;
		}
		return memory_getsampwnam(my_methods, sam_acc, guest_account);
	}

	struct memory_privates *data = (struct memory_privates*)my_methods->private_data;
	struct smb_account *smb_pw = data->pwd;
	for (; smb_pw != NULL; smb_pw = smb_pw->next) {
		if (algorithmic_pdb_uid_to_user_rid(smb_pw->smb_userid) == rid) {
			break;
		}
	}

	/* did we locate the username in memory  */
	if (smb_pw == NULL) {
		return NT_STATUS_UNSUCCESSFUL;
	}

	DEBUG(10, ("getsampwrid (memory): found by name: %s\n", smb_pw->smb_name));

	if (!sam_acc) {
		DEBUG(10,("getsampwrid: (memory) struct samu is NULL\n"));
		return NT_STATUS_UNSUCCESSFUL;
	}

	/* now build the struct samu */
	if (!build_sam_account(sam_acc, smb_pw)) {
		return NT_STATUS_UNSUCCESSFUL;
	}

	/* build_sam_account might change the SID on us, if the name was for the guest account */
	if (!dom_sid_equal(pdb_get_user_sid(sam_acc), sid)) {
		struct dom_sid_buf buf1, buf2;
		DEBUG(1, ("looking for user with sid %s instead returned %s "
			  "for account %s!?!\n",
			  dom_sid_str_buf(sid, &buf1),
			  dom_sid_str_buf(pdb_get_user_sid(sam_acc), &buf2),
			  pdb_get_username(sam_acc)));
		return NT_STATUS_NO_SUCH_USER;
	}

	/* success */
	return NT_STATUS_OK;
}

static NTSTATUS memory_add_sam_account(struct pdb_methods *my_methods, struct samu *sam_acc)
{
	struct memory_privates *data = (struct memory_privates*)my_methods->private_data;

	struct smb_account *new_pw = talloc_zero(my_methods, struct smb_account);
	if (!new_pw) {
		DEBUG(0, ("talloc() failed for memory private_data!\n"));
		return NT_STATUS_NO_MEMORY;
	}

	/* convert the struct samu */
	if (!build_smb_account(new_pw, sam_acc)) {
		return NT_STATUS_UNSUCCESSFUL;
	}

	struct smb_account **p = &(data->pwd);
	for (; *p != NULL; p = &((*p)->next)) {
		if (strequal(new_pw->smb_name, (*p)->smb_name)) {
			DEBUG(0, ("memory_add_sam_account: entry with name %s already exists\n", (*p)->smb_name));
			TALLOC_FREE(new_pw);
			return NT_STATUS_USER_EXISTS;
		}
	}

	*p = new_pw;
	return NT_STATUS_OK;
}

static NTSTATUS memory_delete_sam_account (struct pdb_methods *my_methods, struct samu *sam_acc)
{
	struct memory_privates *mem_data = (struct memory_privates*)my_methods->private_data;
	const char *username = pdb_get_username(sam_acc);

	struct smb_account *pp = NULL;
	struct smb_account *p = mem_data->pwd;
	for (; p != NULL; p = p->next) {
		if (strequal(username, p->smb_name)) {
			break;
		}
		pp = p;
	}

	//can not find account.
	if (p == NULL) {
		return NT_STATUS_UNSUCCESSFUL;
	}

	if (pp != NULL) {
		pp->next = p->next;
	} else {
		mem_data->pwd = NULL; //delete root node
	}

	TALLOC_FREE(p);
	return NT_STATUS_OK;
}

static NTSTATUS memory_update_sam_account(struct pdb_methods *my_methods, struct samu *sam_acc)
{
	if(!NT_STATUS_IS_OK(memory_delete_sam_account(my_methods, sam_acc))) {
		DEBUG(0, ("memory_update_sam_account: memory_delete_sam_account failed!\n"));
		return NT_STATUS_UNSUCCESSFUL;
	}

	if(!NT_STATUS_IS_OK(memory_add_sam_account(my_methods, sam_acc))) {
		DEBUG(0, ("memory_update_sam_account: memory_add_sam_account failed!\n"));
		return NT_STATUS_UNSUCCESSFUL;
	}

	return NT_STATUS_OK;
}

static NTSTATUS memory_rename_sam_account (struct pdb_methods *my_methods, struct samu *old_acc, const char *newname)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

static uint32_t memory_capabilities(struct pdb_methods *methods)
{
	return 0;
}

static void free_private_data(void **vp) 
{
	*vp = NULL;
	/* No need to free any further, as it is talloc()ed */
}

struct memory_search_state {
	uint32_t acct_flags;

	struct samr_displayentry *entries;
	uint32_t num_entries;
	ssize_t array_size;
	uint32_t current;
};

static void memory_search_end(struct pdb_search *search)
{
	struct memory_search_state *state = talloc_get_type_abort(search->private_data, struct memory_search_state);
	TALLOC_FREE(state);
}

static bool memory_search_next_entry(struct pdb_search *search, struct samr_displayentry *entry)
{
	struct memory_search_state *state = talloc_get_type_abort(search->private_data, struct memory_search_state);

	if (state->current == state->num_entries) {
		return false;
	}

	entry->idx = state->entries[state->current].idx;
	entry->rid = state->entries[state->current].rid;
	entry->acct_flags = state->entries[state->current].acct_flags;

	entry->account_name = talloc_strdup(search, state->entries[state->current].account_name);
	entry->fullname = talloc_strdup(search, state->entries[state->current].fullname);
	entry->description = talloc_strdup(search, state->entries[state->current].description);

	if ((entry->account_name == NULL) || (entry->fullname == NULL)|| (entry->description == NULL)) {
		DEBUG(0, ("talloc_strdup failed\n"));
		return false;
	}

	state->current += 1;
	return true;
}

static bool memory_search_users(struct pdb_methods *methods, struct pdb_search *search, uint32_t acct_flags)
{
	struct memory_privates *memory_state = (struct memory_privates*)methods->private_data;

	struct memory_search_state *search_state;
	search_state = talloc_zero(search, struct memory_search_state);
	if (search_state == NULL) {
		DEBUG(0, ("talloc failed\n"));
		return false;
	}
	search_state->acct_flags = acct_flags;

	struct smb_account *pwd = memory_state->pwd;
	for (; pwd != NULL; pwd = pwd->next)  {
		struct samr_displayentry entry;
		struct samu *user;

		if ((acct_flags != 0)
		    && ((acct_flags & pwd->acct_ctrl) == 0)) {
			continue;
		}

		user = samu_new(talloc_tos());
		if (user == NULL) {
			DEBUG(0, ("samu_new failed\n"));
			break;
		}

		if (!build_sam_account(user, pwd)) {
			/* Already got debug msgs... */
			break;
		}

		ZERO_STRUCT(entry);

		entry.acct_flags = pdb_get_acct_ctrl(user);
		sid_peek_rid(pdb_get_user_sid(user), &entry.rid);
		entry.account_name = talloc_strdup(
			search_state, pdb_get_username(user));
		entry.fullname = talloc_strdup(
			search_state, pdb_get_fullname(user));
		entry.description = talloc_strdup(
			search_state, pdb_get_acct_desc(user));

		TALLOC_FREE(user);

		if ((entry.account_name == NULL) || (entry.fullname == NULL) || (entry.description == NULL)) {
			DEBUG(0, ("talloc_strdup failed\n"));
			break;
		}

		ADD_TO_LARGE_ARRAY(search_state, struct samr_displayentry, entry, &search_state->entries,
											&search_state->num_entries,&search_state->array_size);
	}

	search->private_data = search_state;
	search->next_entry = memory_search_next_entry;
	search->search_end = memory_search_end;

	return true;
}

static NTSTATUS pdb_init_memory(struct pdb_methods **pdb_method, const char *location)
{
	NTSTATUS nt_status = make_pdb_method(pdb_method);
	if (!NT_STATUS_IS_OK(nt_status)) {
		return nt_status;
	}

	(*pdb_method)->name = "memory";

	(*pdb_method)->getsampwnam = memory_getsampwnam;
	(*pdb_method)->getsampwsid = memory_getsampwsid;
	(*pdb_method)->add_sam_account = memory_add_sam_account;
	(*pdb_method)->update_sam_account = memory_update_sam_account;
	(*pdb_method)->delete_sam_account = memory_delete_sam_account;
	(*pdb_method)->rename_sam_account = memory_rename_sam_account;
	(*pdb_method)->search_users = memory_search_users;

	(*pdb_method)->capabilities = memory_capabilities;

	/* Setup private data and free function */
	struct memory_privates *privates = talloc_zero(*pdb_method, struct memory_privates);
	if (!privates) {
		DEBUG(0, ("talloc() failed for memory private_data!\n"));
		return NT_STATUS_NO_MEMORY;
	}

	(*pdb_method)->private_data = privates;
	(*pdb_method)->free_private_data = free_private_data;
	return NT_STATUS_OK;
}

NTSTATUS pdb_memory_init(TALLOC_CTX *ctx) 
{
	return smb_register_passdb(PASSDB_INTERFACE_VERSION, "memory", pdb_init_memory);
}
