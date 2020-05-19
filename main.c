/* Sysrepo ietf-interfaces and ietf-ip plugin */

#include "common.h"

int state_cb(sr_session_ctx_t *, const char *, const char *,
	     const char *, unsigned, struct lyd_node **,
	     void *);

int change_cb(sr_session_ctx_t *, const char *, const char *,
	      sr_event_t, unsigned, void *);

int sr_plugin_init_cb(sr_session_ctx_t *sess, void **priv)
{
	int r;
	sr_subscription_ctx_t *sub = NULL;

	openlog("sysrepo ietf-interfaces plugin", LOG_USER, 0);

	if (nlr_init()) {
		ERROR("nlroute init failed");
		return -1;
	}

	r = sr_module_change_subscribe(sess, "ietf-interfaces",
				       "/ietf-interfaces:interfaces",
				        change_cb, NULL, 0,
				        SR_SUBSCR_CTX_REUSE |
				        SR_SUBSCR_ENABLED, &sub);

	if (r != SR_ERR_OK) {
		ERROR("failed to subscribe to changes of ietf-interfaces module: %s",
		      sr_strerror(r));
		goto err;
	}

	r = sr_oper_get_items_subscribe(sess, "ietf-interfaces",
					"/ietf-interfaces:interfaces-state",
					state_cb, NULL,
					SR_SUBSCR_CTX_REUSE, &sub);
	if (r != SR_ERR_OK) {
		ERROR("failed to subscribe to operational data return of ietf-interfaces module: %s",
		      sr_strerror(r));
		goto err;
	}

	*(sr_subscription_ctx_t **)priv = sub;

	DEBUG("init ok");

	return SR_ERR_OK;

err:
	ERROR("init failed: %s", sr_strerror(r));

	sr_unsubscribe(sub);

	nlr_fin();

	return r;
}

void sr_plugin_cleanup_cb(sr_session_ctx_t *session, void *priv)
{
        sr_unsubscribe((sr_subscription_ctx_t *)priv);

	nlr_fin();

        DEBUG("cleanup ok");
}
