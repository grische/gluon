#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <json-c/json.h>
#include <net/if.h>

#include <batadv-genl.h>

#define STR(x) #x
#define XSTR(x) STR(x)

struct neigh_netlink_opts {
	struct json_object *obj;
	struct batadv_nlquery_opts query_opts;
};

/* Algorithm detection */

struct get_algoname_opts {
	char *algoname;
	size_t algoname_len;
	bool found;
	struct batadv_nlquery_opts query_opts;
};

static int get_algoname_cb(struct nl_msg *msg, void *arg) {
	struct nlattr *attrs[BATADV_ATTR_MAX + 1];
	struct get_algoname_opts *opts;
	struct nlmsghdr *nlh = nlmsg_hdr(msg);
	struct batadv_nlquery_opts *query_opts = arg;
	static const enum batadv_nl_attrs mandatory[] = {
		BATADV_ATTR_ALGO_NAME,
	};
	struct genlmsghdr *ghdr;
	const char *algoname;

	opts = batadv_container_of(query_opts, struct get_algoname_opts, query_opts);

	if (!genlmsg_valid_hdr(nlh, 0))
		return NL_OK;

	ghdr = nlmsg_data(nlh);

	if (ghdr->cmd != BATADV_CMD_GET_MESH)
		return NL_OK;

	if (nla_parse(attrs, BATADV_ATTR_MAX, genlmsg_attrdata(ghdr, 0),
				genlmsg_len(ghdr), batadv_genl_policy))
		return NL_OK;

	if (batadv_genl_missing_attrs(attrs, mandatory,
				BATADV_ARRAY_SIZE(mandatory)))
		return NL_OK;

	algoname = nla_data(attrs[BATADV_ATTR_ALGO_NAME]);
	strncpy(opts->algoname, algoname, opts->algoname_len);
	if (opts->algoname_len > 0)
		opts->algoname[opts->algoname_len - 1] = '\0';

	opts->found = true;
	opts->query_opts.err = 0;
	return NL_OK;
}

static int get_algoname(char *algoname, size_t len) {
	struct get_algoname_opts opts = {
		.algoname = algoname,
		.algoname_len = len,
		.found = false,
		.query_opts = { .err = 0 },
	};

	int ret = batadv_genl_query("bat0", BATADV_CMD_GET_MESH,
				get_algoname_cb, 0, &opts.query_opts);
	if (ret < 0)
		return ret;

	if (!opts.found)
		return -EOPNOTSUPP;

	return 0;
}

/* Batman IV: query originators, filter direct neighbors, output TQ percentage */

static const enum batadv_nl_attrs parse_orig_list_mandatory[] = {
	BATADV_ATTR_ORIG_ADDRESS,
	BATADV_ATTR_NEIGH_ADDRESS,
	BATADV_ATTR_TQ,
	BATADV_ATTR_HARD_IFINDEX,
	BATADV_ATTR_LAST_SEEN_MSECS,
};

static int parse_orig_list_netlink_cb(struct nl_msg *msg, void *arg)
{
	struct nlattr *attrs[BATADV_ATTR_MAX+1];
	struct nlmsghdr *nlh = nlmsg_hdr(msg);
	struct batadv_nlquery_opts *query_opts = arg;
	struct genlmsghdr *ghdr;
	uint8_t *orig;
	uint8_t *dest;
	uint8_t tq;
	uint32_t hardif;
	char ifname_buf[IF_NAMESIZE], *ifname;
	struct neigh_netlink_opts *opts;
	char mac1[18];

	opts = batadv_container_of(query_opts, struct neigh_netlink_opts, query_opts);

	if (!genlmsg_valid_hdr(nlh, 0))
		return NL_OK;

	ghdr = nlmsg_data(nlh);

	if (ghdr->cmd != BATADV_CMD_GET_ORIGINATORS)
		return NL_OK;

	if (nla_parse(attrs, BATADV_ATTR_MAX, genlmsg_attrdata(ghdr, 0),
				genlmsg_len(ghdr), batadv_genl_policy))
		return NL_OK;

	if (batadv_genl_missing_attrs(attrs, parse_orig_list_mandatory,
				BATADV_ARRAY_SIZE(parse_orig_list_mandatory)))
		return NL_OK;

	orig = nla_data(attrs[BATADV_ATTR_ORIG_ADDRESS]);
	dest = nla_data(attrs[BATADV_ATTR_NEIGH_ADDRESS]);
	tq = nla_get_u8(attrs[BATADV_ATTR_TQ]);
	hardif = nla_get_u32(attrs[BATADV_ATTR_HARD_IFINDEX]);

	if (memcmp(orig, dest, 6) != 0)
		return NL_OK;

	ifname = if_indextoname(hardif, ifname_buf);
	if (!ifname)
		return NL_OK;

	sprintf(mac1, "%02x:%02x:%02x:%02x:%02x:%02x",
			orig[0], orig[1], orig[2], orig[3], orig[4], orig[5]);

	struct json_object *neigh = json_object_new_object();
	if (!neigh)
		return NL_OK;

	json_object_object_add(neigh, "tq", json_object_new_int(tq * 100 / 255));
	json_object_object_add(neigh, "ifname", json_object_new_string(ifname));
	json_object_object_add(neigh, "best", json_object_new_boolean(nla_get_flag(attrs[BATADV_ATTR_FLAG_BEST])));

	json_object_object_add(opts->obj, mac1, neigh);

	return NL_OK;
}

/* Batman V: query neighbors, output throughput with unit suffix */

static const enum batadv_nl_attrs parse_neigh_list_mandatory[] = {
	BATADV_ATTR_NEIGH_ADDRESS,
	BATADV_ATTR_THROUGHPUT,
	BATADV_ATTR_HARD_IFINDEX,
	BATADV_ATTR_LAST_SEEN_MSECS,
};

static int parse_neigh_list_netlink_cb(struct nl_msg *msg, void *arg)
{
	struct nlattr *attrs[BATADV_ATTR_MAX+1];
	struct nlmsghdr *nlh = nlmsg_hdr(msg);
	struct batadv_nlquery_opts *query_opts = arg;
	struct genlmsghdr *ghdr;
	uint8_t *neigh;
	uint32_t throughput;
	uint32_t hardif;
	char ifname_buf[IF_NAMESIZE], *ifname;
	struct neigh_netlink_opts *opts;
	char mac1[18];
	char tp_str[5];
	const char tp_units[] = {'k', 'M', 'G', 'T', '?'};
	int tp_unit;

	opts = batadv_container_of(query_opts, struct neigh_netlink_opts, query_opts);

	if (!genlmsg_valid_hdr(nlh, 0))
		return NL_OK;

	ghdr = nlmsg_data(nlh);

	if (ghdr->cmd != BATADV_CMD_GET_NEIGHBORS)
		return NL_OK;

	if (nla_parse(attrs, BATADV_ATTR_MAX, genlmsg_attrdata(ghdr, 0),
				genlmsg_len(ghdr), batadv_genl_policy))
		return NL_OK;

	if (batadv_genl_missing_attrs(attrs, parse_neigh_list_mandatory,
				BATADV_ARRAY_SIZE(parse_neigh_list_mandatory)))
		return NL_OK;

	neigh = nla_data(attrs[BATADV_ATTR_NEIGH_ADDRESS]);
	throughput = nla_get_u32(attrs[BATADV_ATTR_THROUGHPUT]);
	hardif = nla_get_u32(attrs[BATADV_ATTR_HARD_IFINDEX]);

	ifname = if_indextoname(hardif, ifname_buf);
	if (!ifname)
		return NL_OK;

	sprintf(mac1, "%02x:%02x:%02x:%02x:%02x:%02x",
			neigh[0], neigh[1], neigh[2], neigh[3], neigh[4], neigh[5]);

	struct json_object *obj = json_object_new_object();
	if (!obj)
		return NL_OK;

	for (tp_unit = 0; tp_unit < 4; tp_unit++) {
		if (throughput < 1000)
			break;
		throughput /= 1000;
	}
	sprintf(tp_str, "%3u%c", throughput, tp_units[tp_unit]);

	json_object_object_add(obj, "tp", json_object_new_string(tp_str));
	json_object_object_add(obj, "ifname", json_object_new_string(ifname));
	json_object_object_add(obj, "best", json_object_new_boolean(nla_get_flag(attrs[BATADV_ATTR_FLAG_BEST])));

	json_object_object_add(opts->obj, mac1, obj);

	return NL_OK;
}

static json_object *neighbours(void) {
	struct neigh_netlink_opts opts = {
		.query_opts = {
			.err = 0,
		},
	};
	int ret;
	char algoname[256];

	opts.obj = json_object_new_object();
	if (!opts.obj)
		return NULL;

	if (get_algoname(algoname, sizeof(algoname)) < 0) {
		json_object_put(opts.obj);
		return NULL;
	}

	if (strcmp(algoname, "BATMAN_IV") == 0) {
		ret = batadv_genl_query("bat0", BATADV_CMD_GET_ORIGINATORS,
				parse_orig_list_netlink_cb, NLM_F_DUMP,
				&opts.query_opts);
	} else if (strcmp(algoname, "BATMAN_V") == 0) {
		ret = batadv_genl_query("bat0", BATADV_CMD_GET_NEIGHBORS,
				parse_neigh_list_netlink_cb, NLM_F_DUMP,
				&opts.query_opts);
	} else {
		json_object_put(opts.obj);
		return NULL;
	}

	if (ret < 0) {
		json_object_put(opts.obj);
		return NULL;
	}

	return opts.obj;
}

int main(void) {
	struct json_object *obj;

	printf("Content-type: text/event-stream\n\n");
	fflush(stdout);

	while (1) {
		obj = neighbours();
		if (obj) {
			printf("data: %s\n\n", json_object_to_json_string_ext(obj, JSON_C_TO_STRING_PLAIN));
			fflush(stdout);
			json_object_put(obj);
		}
		sleep(10);
	}

	return 0;
}
