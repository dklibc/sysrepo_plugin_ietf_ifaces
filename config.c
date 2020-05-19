/*
 * Changing config data callback (of 'ietf-interfaces:interfaces'
 * subtree). Validate changes and apply them.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "common.h"

enum ac_type {
	AC_UNKNOWN,
	AC_CREATE_IFACE,
	AC_DEL_IFACE,
	AC_ADD_ADDR,
	AC_DEL_ADDR,
	AC_ENABLE_IFACE,
	AC_DISABLE_IFACE,
};

struct action {
	enum ac_type type;
	struct action *pnext;
	char *iface;
	union {
		struct {
			in_addr_t addr;
			int prefix_len;
		} ip;
	} param;
};

static void free_action(struct action *ac)
{
	struct action *_ac;

	while (ac) {
		_ac = ac->pnext;

		free(ac->iface);

		free(ac);

		ac = _ac;
	}
}

/* Find action in the list or create a new one. */
static struct action *get_action(struct action **ac_list,
				 const char *iface,
				 enum ac_type type, int search)
{
	struct action *ac;

	/* Compare only with the action in the list head,
	since 'changes' of the same subtree are groupped together. */
	ac = *ac_list;
	if (search && ac && ac->type == type
	    && !strcmp(ac->iface, iface))
		return ac;

	/* We must init an action struct here, so that
	a caller see what fields are unset. */
	ac = calloc(sizeof(*ac), 1);
	if (!ac) {
		ERROR("failed to alloc action");
		return NULL;
	}

	ac->type = type;

	ac->iface = strdup(iface);
	if (!ac->iface) {
		ERROR("failed to strdup iface name");
		free(ac);
		return NULL;
	}

	ac->pnext = *ac_list;
	*ac_list = ac;

	return ac;
}

/*
 * Helper function, called on
 * "CREATED/DELETED /ietf-interfaces:interfaces/interface[name='foo']"
 * change. Add a corresponfing action to the list.
 */
static int do_iface(sr_change_oper_t op, sr_val_t *old_val,
		    sr_val_t *new_val, struct action **ac_list,
		    const char *iface)
{
	switch(op) {
		case SR_OP_CREATED:
			if (!get_action(ac_list, iface,
					AC_CREATE_IFACE, 0)) {
				return SR_ERR_SYS;
			}

			break;

		case SR_OP_DELETED:
			if (!get_action(ac_list, iface,
					AC_DEL_IFACE, 0)) {
				return SR_ERR_SYS;
			}

			break;
	}

	return SR_ERR_OK;

}

/*
 * Helper function, called on
 * "CREATED/DELETED/MODIFIED \
 *   /ietf-interfaces:interfaces/interface[name='foo']/enabled"
 * Default value of 'enebled' leaf is 'true'.
 * Add a corresponding action to the list.
 */
static int do_enabled(sr_change_oper_t op, sr_val_t *old_val,
		      sr_val_t *new_val, struct action **ac_list,
		      const char *iface)
{
	switch(op) {
		case SR_OP_CREATED:
		case SR_OP_MODIFIED:
			if (!get_action(ac_list, iface,
					new_val->data.bool_val ?
					AC_ENABLE_IFACE
					: AC_DISABLE_IFACE, 0)) {
				return SR_ERR_SYS;
			}
			break;

		case SR_OP_DELETED:
			if (!old_val->data.bool_val) {
				if (!get_action(ac_list, iface,
						AC_ENABLE_IFACE, 0)) {
					return SR_ERR_SYS;
				}
			}
			break;
	}

	return SR_ERR_OK;
}

/*
 * Helper function, called on
 *  'CREATED/DELETED/MODIFIED \
 *    /ietf-interfaces:interfaces/interface[name='foo'] \
 *      /ietf-ip:ipv4/address[ip='a.b.c.d']/prefix-length'
 * 'prefix-length' leaf is mandatory, so it is always be changed when ip
 * address is created or deleted.
 * Add a corresponding action to the list.
 */
static int do_prefix_len(sr_change_oper_t op, sr_val_t *old_val,
			 sr_val_t *new_val, struct action **ac_list,
			 const char *iface, const char *ip)
{
	struct in_addr in_addr;
	struct action *ac = NULL;

	switch(op) {
		case SR_OP_CREATED:
			ac = get_action(ac_list, iface, AC_ADD_ADDR, 1);
			if (!ac)
				return SR_ERR_SYS;

			ac->param.ip.prefix_len =
				new_val->data.uint8_val;
			break;

		case SR_OP_DELETED:
			ac = get_action(ac_list, iface, AC_DEL_ADDR, 1);
			if (!ac)
				return SR_ERR_SYS;

			ac->param.ip.prefix_len =
				old_val->data.uint8_val;

			break;

		case SR_OP_MODIFIED:
			ac = get_action(ac_list, iface, AC_DEL_ADDR, 0);
			if (!ac)
				return SR_ERR_SYS;

			ac->param.ip.prefix_len =
				old_val->data.uint8_val;

			inet_aton(ip, &in_addr);
			ac->param.ip.addr = in_addr.s_addr;

			ac = get_action(ac_list, iface, AC_ADD_ADDR, 0);
			if (!ac)
				return SR_ERR_SYS;

			ac->param.ip.prefix_len =
				new_val->data.uint8_val;

			break;
	}

	if (ac) {
		inet_aton(ip, &in_addr);
		ac->param.ip.addr = in_addr.s_addr;
	}

	return SR_ERR_OK;
}

struct iface_idx {
	char *name;
	int idx;
	struct iface_idx *pnext;
};

static struct iface_idx *iface_idx;

static void clear_iface_idx_cache(void)
{
	struct iface_idx *p, *q;

	p = iface_idx;
	while (p) {
		q = p->pnext;
		free(p->name);
		free(p);
		p = q;
	}

	iface_idx = NULL;
}

static int get_iface_idx(const char *name)
{
	struct iface_idx *p;
	int idx;

	for (p = iface_idx; p; p++) {
		if (!strcmp(p->name, name))
			return p->idx;
	}

	idx = nlr_iface_idx(name);
	if (idx < 0) {
		ERROR("failed to get index of %s", name);
		return -1;
	}

	p = malloc(sizeof(struct iface_idx));
	if (!p) {
		ERROR("failed to alloc iface idx cache entry");
		return -1;
	}

	p->name = strdup(name);
	if (!p->name) {
		free(p);
		ERROR("failed to strdup iface name");
		return -1;
	}

	p->idx = idx;

	p->pnext = iface_idx;

	if (!iface_idx)
		iface_idx = p;

	return idx;
}

static int apply_iface_changes(sr_session_ctx_t *session,
			       struct action *ac_list)
{
	struct action *ac;
	struct in_addr in_addr;
	const char *ip;
	char xpath[256];
	sr_val_t *val;
	int r, idx;

	/* First delete all addresses */
	for (ac = ac_list; ac; ac = ac->pnext) {
		if (ac->type != AC_DEL_ADDR)
			continue;

		in_addr.s_addr = ac->param.ip.addr;
		ip = inet_ntoa(in_addr);
		DEBUG("deleting addr %s/%d from %s",
		      ip, ac->param.ip.prefix_len, ac->iface);

		idx = get_iface_idx(ac->iface);
		if (idx < 0) {
			ERROR("failed to get idx of '%s', skip deleting addr",
			      ac->iface);
			continue;
		}

		if (nlr_del_addr(idx, ac->param.ip.addr,
				 ac->param.ip.prefix_len)) {
			ERROR("failed to del addr");
			continue;
		}
	}

	/* Next delete all ifaces */
	for (ac = ac_list; ac; ac = ac->pnext) {
		if (ac->type != AC_DEL_IFACE)
			continue;

		DEBUG("deleting iface %s", ac->iface);

		idx = get_iface_idx(ac->iface);
		if (idx < 0) {
			ERROR("failed to get index of '%s', skip deleting",
			      ac->iface);
			continue;
		}

		if (nlr_set_iface(idx, 0)) {
			ERROR("failed to set iface down");
			continue;
		}
	}

	/* Next create all ifaces */
	for (ac = ac_list; ac; ac = ac->pnext) {
		if (ac->type != AC_CREATE_IFACE)
			continue;
		DEBUG("creating iface %s", ac->iface);
	}

	/* Next add all addresses */
	for (ac = ac_list; ac; ac = ac->pnext) {
		if (ac->type != AC_ADD_ADDR)
			continue;

		in_addr.s_addr = ac->param.ip.addr;
		ip = inet_ntoa(in_addr);
		DEBUG("adding addr %s/%d to %s",
		      ip, ac->param.ip.prefix_len, ac->iface);

		idx = get_iface_idx(ac->iface);
		if (idx < 0) {
			ERROR("failed to get index of '%s', skip adding addr",
			      ac->iface);
			continue;
		}

		if (nlr_add_addr(idx, ac->param.ip.addr,
				 ac->param.ip.prefix_len)) {
			ERROR("failed to add addr");
			continue;
		}
	}

	/* Next enable/disable all existing ifaces */
	for (ac = ac_list; ac; ac = ac->pnext) {
		if (ac->type != AC_ENABLE_IFACE
		    && ac->type != AC_DISABLE_IFACE) {
			continue;
		}

		DEBUG("setting iface %s %s", ac->iface,
		      ac->type == AC_ENABLE_IFACE ? "up" : "down");

		idx = get_iface_idx(ac->iface);
		if (idx < 0) {
			ERROR("failed to get index of '%s', skip setting iface",
			      ac->iface);
			continue;
		}

		if (nlr_set_iface(idx, ac->type == AC_ENABLE_IFACE ?
				  1 : 0)) {
			ERROR("failed to set iface");
			continue;
		}
	}

	clear_iface_idx_cache();
}

/*
 * Helper function. Used for getting key value from XPath.
 * E.g. iface name 'foo' from:
 *   '/ietf-interfaces:interfaces/interface[name='foo']'
 * ip 'a.b.c.d' from:
 *   '/ietf-ip:ipv4/address[ip='a.b.c.d']/prefix-length
 */
static char *xpath_key_val(char *xpath, const char *prefix, char **tail)
{
	int n = strlen(prefix);
	char *p;

	if (strncmp(xpath, prefix, n))
		return NULL;

	for (p = xpath + n; *p != '\''; p++) {
		if (!*p)
			return NULL;
	}

	if (*(p + 1) != ']')
		return NULL;

	*p = '\0';

	*tail = p + 2;

	return xpath + n;
}

/* For debug output only */
static const char *sr_op2str(sr_change_oper_t op)
{
	switch(op) {
		case SR_OP_MODIFIED:
			return "MODIFIED";
		case SR_OP_CREATED:
			return "CREATED";
		case SR_OP_DELETED:
			return "DELETED";
		default:
			return "(UNKNOWN)";
	}
}

/* For debug output only */
static const char *sr_event2str(sr_event_t event)
{
	switch(event) {
		case SR_EV_CHANGE: /* Verify changes */
			return "VERIFY";
		case SR_EV_DONE:
			/* Apply changes (they are already in DB) */
			return "APPLY";
		case SR_EV_ABORT:
			/* Some of subscribers hasn't verified changes*/
			return "ABORT";
		case SR_EV_ENABLED:
			/* Verify existed config while subscribing */
			return "VERIFY-WHEN-SUBSCR";
		default:
			return "(UNKNOWN)";
	}
}

//#define LOG_FILE "/home/user/sysrepo_plugin_ietf_ifaces/sr_log"
#define LOG_FILE "/dev/null"

int change_cb(sr_session_ctx_t *session, const char *module,
	      const char *_xpath, sr_event_t event, unsigned request_id,
	      void *priv)
{
	int r;
	sr_change_iter_t *iter;
	sr_change_oper_t op;
	sr_val_t *old_val, *new_val;
	FILE *fp = NULL;
	char *iface, *ip, *p;
	char xpath[256];

	static struct action *ac_list;

	if (event == SR_EV_ABORT) {
		free_action(ac_list);
		ac_list = NULL;
		return SR_ERR_OK;
	}

	if (event == SR_EV_DONE) {
		r = apply_iface_changes(session, ac_list);
		free_action(ac_list);
		ac_list = NULL;
		return r;
	}

	/* SR_EV_CHANGE or SR_EV_ENABLED */

	strncpy(xpath, _xpath, sizeof(xpath));

	r = sr_get_changes_iter(session, "//.", &iter);
	if (r != SR_ERR_OK) {
		ERROR("failed to get changes iter: %s", sr_strerror(r));
		return r;
	}

	fp = fopen(LOG_FILE, "a");

	fprintf(fp, "\n%s-------------------------------------\n",
		sr_event2str(event));

	ac_list = NULL;
	r = SR_ERR_OK;
	while (sr_get_change_next(session, iter, &op, &old_val,
		&new_val) == SR_ERR_OK && r == SR_ERR_OK) {
		r = SR_ERR_OK;

		fprintf(fp, "%s %s\n", sr_op2str(op),
			old_val ? old_val->xpath : new_val->xpath);

		iface = xpath_key_val(old_val ? old_val->xpath :
				      new_val->xpath,
				      "/ietf-interfaces:interfaces/interface[name='",
				      &p);
		if (!iface)
			goto free_vals;

		if (!*p) {
			r = do_iface(op, old_val, new_val,
				     &ac_list, iface);
		} else if (!strcmp(p, "/enabled")) {
			r = do_enabled(op, old_val, new_val,
				       &ac_list, iface);
		} else {
			ip = xpath_key_val(p,
					   "/ietf-ip:ipv4/address[ip='",
					   &p);
			if (!ip)
				goto free_vals;

			if (!strcmp(p, "/prefix-length")) {
				r = do_prefix_len(op, old_val,
						  new_val, &ac_list,
						  iface, ip);
			}
		}

free_vals:
		sr_free_val(old_val);
		sr_free_val(new_val);
	}

	fclose(fp);

	return r;
}
