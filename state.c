/* 'ietf-interfaces:interfaces-state' operational data callback */

#include <stdio.h>
#include <string.h>

#include "common.h"

static const char *iana_iface_type(struct nlr_iface *iface)
{
	if (iface->type == NLR_IFACE_ETHER)
		return "ethernetCsmacd";
	else if (iface->type == NLR_IFACE_LOOPBACK)
		return "softwareLoopback";
	else
		return NULL;
}

/*
static const char *node_name(struct lyd_node *node)
{
	if (!node || !node->schema)
		return "(null)";

	return node->schema->name;
}

static const char *node_type2str(struct lyd_node *node)
{
	if (!node || !node->schema)
		return "(null)";

	switch(node->schema->nodetype) {
		case LYS_CONTAINER:
			return "container";
		case LYS_LEAF:
			return "leaf";
		case LYS_LEAFLIST:
			return "leaf-list";
		case LYS_LIST:
			return "list";
		default:
			return "unknown";
	}
}

#define LOGNODE(p) DEBUG("%d: p=%p, name=%s, type=%s", __LINE__, p, node_name(p), node_type2str(p))
*/

#define LOGNODE(p)

#define IFACE_STATE_PATH "/ietf-interfaces:interfaces-state"

int state_cb(sr_session_ctx_t *session, const char *module,
	     const char *_path, const char *request_path,
	     unsigned request_id, struct lyd_node **parent,
	     void *priv)
{
	char buf[64], *s;
	struct nlr_iface *iface, *_iface;
	struct nlr_addr *addr, *_addr;
	int err;
	struct lyd_node *p;
	struct in_addr in;

	//DEBUG("path=%s request_path=%s", _path, request_path);

	iface = nlr_iface(-1, &err);
	if (!iface)
		return !err ? SR_ERR_OK : SR_ERR_SYS;

	p = lyd_new_path(NULL,
			 sr_get_context(sr_session_get_connection(session)),
			 IFACE_STATE_PATH, NULL, 0, 0);
	*parent = p;

	for (_iface = iface; iface; iface = iface->pnext) {
		LOGNODE(p);

		snprintf(buf, sizeof(buf), "interface[name='%s']",
			 iface->name);
		p = lyd_new_path(p, NULL, buf, NULL, 0, 0);
		LOGNODE(p);
		if (!p) {
			ERROR("%d p is null", __LINE__);
fail:
			nlr_iface_free(_iface);
			return SR_ERR_SYS;
		}

		snprintf(buf, sizeof(buf), "iana-if-type:%s",
			 iana_iface_type(iface));
		lyd_new_path(p, NULL, "type", buf, 0, 0);

		lyd_new_path(p, NULL, "admin-status",
			     iface->is_up ? "up" : "down", 0, 0);

		lyd_new_path(p, NULL, "oper-status",
			     iface->carrier_on ? "up" : "down", 0, 0);

		snprintf(buf, sizeof(buf), "%d", iface->idx);
		lyd_new_path(p, NULL, "if-index", buf, 0, 0);

		snprintf(buf, sizeof(buf),
			"%02x:%02x:%02x:%02x:%02x:%02x", iface->mac[0],
			iface->mac[1], iface->mac[2], iface->mac[3],
			iface->mac[4], iface->mac[5]);
		lyd_new_path(p, NULL, "phys-address", buf, 0, 0);

		addr = nlr_get_addr(iface->idx, &err);
		if (!err && addr) {
			p = lyd_new_path(p, NULL, "ietf-ip:ipv4", NULL,
					 0, 0);
			LOGNODE(p);

			snprintf(buf, sizeof(buf), "%d", iface->mtu);
			lyd_new_path(p, NULL, "ietf-ip:mtu", buf, 0, 0);

			p = lyd_new_path(p, NULL, "ietf-ip:address",
					 NULL, 0, 0);
			LOGNODE(p);

			for (_addr = addr; addr; addr = addr->pnext) {
				in.s_addr = addr->addr;
				lyd_new_path(p, NULL, "ietf-ip:ip",
					     inet_ntoa(in), 0, 0);

				snprintf(buf, sizeof(buf), "%d",
					 addr->prefix_len);
				lyd_new_path(p, NULL,
					     "ietf-ip:prefix-length",
					     buf, 0, 0);
			}

			if (!p || !p->parent) {
				ERROR("%d p or p->parent is null, p=%p",
				      __LINE__, p);
				nlr_addr_free(_addr);
				goto fail;
			}

			p = p->parent->parent;

			nlr_addr_free(_addr);
		}

		p = lyd_new_path(p, NULL, "statistics", NULL, 0, 0);
		LOGNODE(p);

		/* TODO */
		snprintf(buf, sizeof(buf), "2020-01-01T00:00:00+03:00");
		lyd_new_path(p, NULL, "discontinuity-time", buf, 0, 0);

		snprintf(buf, sizeof(buf), "%ld",
			 iface->stats.rx_bytes);
		lyd_new_path(p, NULL, "in-octets", buf, 0, 0);

		snprintf(buf, sizeof(buf), "%ld",
			 iface->stats.rx_packets);
		lyd_new_path(p, NULL, "in-unicast-pkts", buf, 0, 0);

		snprintf(buf, sizeof(buf), "%ld",
			 iface->stats.tx_bytes);
		lyd_new_path(p, NULL, "out-octets", buf, 0, 0);

		snprintf(buf, sizeof(buf), "%ld",
			 iface->stats.tx_packets);
		lyd_new_path(p, NULL, "out-unicast-pkts", buf, 0, 0);

		if (!p || !p->parent) {
			ERROR("%d p or p->parent is null, p=%p",
			      __LINE__, p);
			goto fail;
		}
		p = p->parent->parent;

		/*
		lyd_print_mem(&s, p, LYD_XML, 0);
		DEBUG("%s", s);
		*/
	}

	nlr_iface_free(_iface);

	return SR_ERR_OK;
}
