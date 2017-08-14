/*
 * Copyright (C) 2017 John Crispin <john@phrozen.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include "udevmand.h"

struct family_data {
	const char *group;
	int id;
};

static struct nl_socket nl80211_status;
static uint8_t nl80211_arg[4096];

static struct nlattr *sinfo[NL80211_STA_INFO_MAX + 1];
static struct nlattr *rinfo[NL80211_RATE_INFO_MAX + 1];

static struct nla_policy stats_policy[NL80211_STA_INFO_MAX + 1] = {
	[NL80211_STA_INFO_INACTIVE_TIME] = { .type = NLA_U32    },
	[NL80211_STA_INFO_RX_PACKETS]    = { .type = NLA_U32    },
	[NL80211_STA_INFO_TX_PACKETS]    = { .type = NLA_U32    },
	[NL80211_STA_INFO_RX_BITRATE]    = { .type = NLA_NESTED },
	[NL80211_STA_INFO_TX_BITRATE]    = { .type = NLA_NESTED },
	[NL80211_STA_INFO_SIGNAL]        = { .type = NLA_U8     },
	[NL80211_STA_INFO_RX_BYTES]      = { .type = NLA_U32    },
	[NL80211_STA_INFO_TX_BYTES]      = { .type = NLA_U32    },
	[NL80211_STA_INFO_TX_RETRIES]    = { .type = NLA_U32    },
	[NL80211_STA_INFO_TX_FAILED]     = { .type = NLA_U32    },
	[NL80211_STA_INFO_T_OFFSET]      = { .type = NLA_U64    },
	[NL80211_STA_INFO_STA_FLAGS] =
		{ .minlen = sizeof(struct nl80211_sta_flag_update) },
};

static struct nla_policy rate_policy[NL80211_RATE_INFO_MAX + 1] = {
	[NL80211_RATE_INFO_BITRATE]      = { .type = NLA_U16    },
	[NL80211_RATE_INFO_MCS]          = { .type = NLA_U8     },
	[NL80211_RATE_INFO_40_MHZ_WIDTH] = { .type = NLA_FLAG   },
	[NL80211_RATE_INFO_SHORT_GI]     = { .type = NLA_FLAG   },
};

static int
avl_addrcmp(const void *k1, const void *k2, void *ptr)
{
	return memcmp(k1, k2, 6);
}

static struct avl_tree wif_tree = AVL_TREE_INIT(wif_tree, avl_strcmp, false, NULL);
static struct avl_tree sta_tree = AVL_TREE_INIT(sta_tree, avl_addrcmp, false, NULL);

static int
nl80211_freq2channel(int freq)
{
        if (freq == 2484)
                return 14;
        else if (freq < 2484)
                return (freq - 2407) / 5;
        else if (freq >= 4910 && freq <= 4980)
                return (freq - 4000) / 5;
        else if(freq >= 56160 + 2160 * 1 && freq <= 56160 + 2160 * 6)
                return (freq - 56160) / 2160;
        else
                return (freq - 5000) / 5;
}

static void
nl80211_parse_rateinfo(struct nlattr **ri, char *table)
{
	int mhz = 0;
	void *cookie = blobmsg_open_table(&b, table);

	if (ri[NL80211_RATE_INFO_BITRATE32])
		blobmsg_add_u32(&b, "bitrate", nla_get_u32(ri[NL80211_RATE_INFO_BITRATE32]) * 100);
	else if (ri[NL80211_RATE_INFO_BITRATE])
		blobmsg_add_u16(&b, "bitrate", nla_get_u16(ri[NL80211_RATE_INFO_BITRATE]) * 100);

	if (ri[NL80211_RATE_INFO_VHT_MCS]) {
		blobmsg_add_u8(&b, "vht", 1);
		blobmsg_add_u8(&b, "mcs", nla_get_u8(ri[NL80211_RATE_INFO_VHT_MCS]));

		if (ri[NL80211_RATE_INFO_VHT_NSS])
			blobmsg_add_u8(&b, "nss", nla_get_u8(ri[NL80211_RATE_INFO_VHT_NSS]));
	} else if (ri[NL80211_RATE_INFO_MCS]) {
		blobmsg_add_u8(&b, "ht", 1);
		blobmsg_add_u8(&b, "mcs", nla_get_u8(ri[NL80211_RATE_INFO_MCS]));
	}

	if (ri[NL80211_RATE_INFO_5_MHZ_WIDTH])
		mhz = 5;
	else if (ri[NL80211_RATE_INFO_10_MHZ_WIDTH])
		mhz = 10;
	else if (ri[NL80211_RATE_INFO_40_MHZ_WIDTH])
		mhz = 40;
	else if (ri[NL80211_RATE_INFO_80_MHZ_WIDTH])
		mhz = 80;
	else if (ri[NL80211_RATE_INFO_80P80_MHZ_WIDTH] ||
		 ri[NL80211_RATE_INFO_160_MHZ_WIDTH])
		mhz = 160;
	else
		mhz = 20;
	blobmsg_add_u32(&b, "mhz", mhz);

	if (ri[NL80211_RATE_INFO_SHORT_GI])
		blobmsg_add_u8(&b, "short_gi", 1);
	blobmsg_close_table(&b, cookie);
}

static void
nl80211_to_blob(struct nlattr **tb, char *ifname)
{
	memset(sinfo, 0, sizeof(sinfo));
	memset(rinfo, 0, sizeof(rinfo));

	blob_buf_init(&b, 0);

	if (tb[NL80211_ATTR_IFINDEX]) {
		int idx = nla_get_u32(tb[NL80211_ATTR_IFINDEX]);
		if (ifname)
			if_indextoname(idx, ifname);
	} else if (tb[NL80211_ATTR_IFNAME]) {
		if (ifname)
			ifname = nla_get_string(tb[NL80211_ATTR_IFNAME]);
	}

	if (tb[NL80211_ATTR_WIPHY])
		blobmsg_add_u32(&b, "phy", nla_get_u32(tb[NL80211_ATTR_WIPHY]));

	if (tb[NL80211_ATTR_SSID])
		blobmsg_add_string(&b, "ssid", nla_get_string(tb[NL80211_ATTR_SSID]));

	if (tb[NL80211_ATTR_IFTYPE])
		blobmsg_add_iftype(&b, "iftype", nla_get_u32(tb[NL80211_ATTR_IFTYPE]));

	if (tb[NL80211_ATTR_WIPHY_TX_POWER_LEVEL])
		blobmsg_add_u32(&b, "txpower", nla_get_u32(tb[NL80211_ATTR_WIPHY_TX_POWER_LEVEL]) / 100);

	if (tb[NL80211_ATTR_WIPHY_FREQ]) {
		blobmsg_add_u32(&b, "frequency", nla_get_u32(tb[NL80211_ATTR_WIPHY_FREQ]));
		blobmsg_add_u32(&b, "channel", nl80211_freq2channel(nla_get_u32(tb[NL80211_ATTR_WIPHY_FREQ])));
	}
	if (tb[NL80211_ATTR_CENTER_FREQ1])
		blobmsg_add_u32(&b, "center_freq1", nla_get_u32(tb[NL80211_ATTR_CENTER_FREQ1]));

	if (tb[NL80211_ATTR_CENTER_FREQ2])
		blobmsg_add_u32(&b, "center_freq2", nla_get_u32(tb[NL80211_ATTR_CENTER_FREQ2]));

	if (tb[NL80211_ATTR_CHANNEL_WIDTH])
		switch(nla_get_u32(tb[NL80211_ATTR_CHANNEL_WIDTH])) {
		case NL80211_CHAN_WIDTH_20:
			blobmsg_add_string(&b, "channel_width", "20");
			break;
		case NL80211_CHAN_WIDTH_40:
			blobmsg_add_string(&b, "channel_width", "40");
			break;
		case NL80211_CHAN_WIDTH_80:
			blobmsg_add_string(&b, "channel_width", "80");
			break;
		case NL80211_CHAN_WIDTH_80P80:
			blobmsg_add_string(&b, "channel_width", "80p80");
			break;
		case NL80211_CHAN_WIDTH_160:
			blobmsg_add_string(&b, "channel_width", "160");
			break;
		}

	if (tb[NL80211_ATTR_WIPHY_CHANNEL_TYPE])
		blobmsg_add_u32(&b, "channel_type", nla_get_u32(tb[NL80211_ATTR_WIPHY_CHANNEL_TYPE]));

	if (tb[NL80211_ATTR_STA_INFO] != NULL &&
	    !nla_parse_nested(sinfo, NL80211_STA_INFO_MAX,
			      tb[NL80211_ATTR_STA_INFO], stats_policy))
	{
		if (sinfo[NL80211_STA_INFO_SIGNAL])
			blobmsg_add_u32(&b, "signal", (signed char)nla_get_u8(sinfo[NL80211_STA_INFO_SIGNAL]));
		if (sinfo[NL80211_STA_INFO_INACTIVE_TIME])
			blobmsg_add_u32(&b, "inactive", nla_get_u32(sinfo[NL80211_STA_INFO_INACTIVE_TIME]));
		if (sinfo[NL80211_STA_INFO_RX_PACKETS])
			blobmsg_add_u32(&b, "rx_pkt", nla_get_u32(sinfo[NL80211_STA_INFO_RX_PACKETS]));
		if (sinfo[NL80211_STA_INFO_TX_PACKETS])
			blobmsg_add_u32(&b, "tx_pkt", nla_get_u32(sinfo[NL80211_STA_INFO_TX_PACKETS]));
		if (sinfo[NL80211_STA_INFO_RX_BITRATE] &&
		    !nla_parse_nested(rinfo, NL80211_RATE_INFO_MAX, sinfo[NL80211_STA_INFO_RX_BITRATE],
				      rate_policy))
			nl80211_parse_rateinfo(rinfo, "rx_rate");
		if (sinfo[NL80211_STA_INFO_TX_BITRATE] &&
		    !nla_parse_nested(rinfo, NL80211_RATE_INFO_MAX, sinfo[NL80211_STA_INFO_TX_BITRATE],
				      rate_policy))
			nl80211_parse_rateinfo(rinfo, "tx_rate");
		if (sinfo[NL80211_STA_INFO_RX_BYTES])
			blobmsg_add_u32(&b, "rx_bytes", nla_get_u32(sinfo[NL80211_STA_INFO_RX_BYTES]));
		if (sinfo[NL80211_STA_INFO_TX_BYTES])
			blobmsg_add_u32(&b, "tx_bytes", nla_get_u32(sinfo[NL80211_STA_INFO_TX_BYTES]));
		if (sinfo[NL80211_STA_INFO_TX_RETRIES])
			blobmsg_add_u32(&b, "tx_retries", nla_get_u32(sinfo[NL80211_STA_INFO_TX_RETRIES]));
		if (sinfo[NL80211_STA_INFO_TX_FAILED])
			blobmsg_add_u32(&b, "tx_failed", nla_get_u32(sinfo[NL80211_STA_INFO_TX_FAILED]));
		if (sinfo[NL80211_STA_INFO_T_OFFSET])
			blobmsg_add_u32(&b, "tx_offset", nla_get_u32(sinfo[NL80211_STA_INFO_T_OFFSET]));
	}

	if (tb[NL80211_ATTR_REG_ALPHA2])
		blobmsg_add_string(&b, "country", nla_get_string(tb[NL80211_ATTR_REG_ALPHA2]));

	if (tb[NL80211_ATTR_DFS_REGION])
		blobmsg_add_u16(&b, "dfs-region", nla_get_u8(tb[NL80211_ATTR_DFS_REGION]));
}

static void
nl80211_list_wif(void)
{
	struct nl_msg *msg;

	msg = nlmsg_alloc();
	if (!msg)
		return;

	if (!genlmsg_put(msg, 0, 0, genl_ctrl_resolve(nl80211_status.sock, "nl80211"),
			 0, NLM_F_DUMP, NL80211_CMD_GET_INTERFACE, 0)) {
		nlmsg_free(msg);
		return;
	}

	genl_send_and_recv(&nl80211_status, msg);
}

static void
nl80211_assoc_list(struct uloop_timeout *t)
{
	struct wifi_iface *wif = container_of(t, struct wifi_iface, assoc);
	struct nl_msg *msg;
	int idx = if_nametoindex(wif->ifname);

	msg = nlmsg_alloc();
	if (!msg)
		goto out;

	if (!genlmsg_put(msg, 0, 0, genl_ctrl_resolve(nl80211_status.sock, "nl80211"),
			 0, NLM_F_DUMP, NL80211_CMD_GET_STATION, 0) ||
		nla_put_u32(msg, NL80211_ATTR_IFINDEX, idx)) {
		nlmsg_free(msg);
		goto out;
	}

	genl_send_and_recv(&nl80211_status, msg);

	msg = nlmsg_alloc();
	if (!msg)
		goto out;

	if (!genlmsg_put(msg, 0, 0, genl_ctrl_resolve(nl80211_status.sock, "nl80211"),
			 0, NLM_F_DUMP, NL80211_CMD_GET_SURVEY, 0) ||
		nla_put_u32(msg, NL80211_ATTR_IFINDEX, idx)) {
		nlmsg_free(msg);
		goto out;
	}

	genl_send_and_recv(&nl80211_status, msg);

out:
	uloop_timeout_set(t, 30 * 1000);
}

static void
nl80211_add_station(struct nlattr **tb, char *ifname)
{
	struct wifi_station *sta;
	struct mac *mac;
	uint8_t *addr;

	if (tb[NL80211_ATTR_MAC] == NULL)
		return;

	nl80211_to_blob(tb, ifname);
	addr = nla_data(tb[NL80211_ATTR_MAC]);

	mac = mac_find(addr);
	sta = avl_find_element(&sta_tree, addr, sta, avl);
	if (!sta) {
		struct wifi_iface *wif;

		wif = avl_find_element(&wif_tree, ifname, wif, avl);
		if (!wif)
			return;
		sta = malloc(sizeof(*sta));
		if (!sta)
			return;

		memset(sta, 0, sizeof(*sta));
		memcpy(sta->addr, addr, 6);
		sta->avl.key = sta->addr;
		sta->wif = wif;
		sta->info = NULL;
		avl_insert(&sta_tree, &sta->avl);
		list_add(&sta->mac, &mac->wifi);
		list_add(&sta->iface, &wif->stas);
		ULOG_INFO("new station %s "MAC_FMT"\n", ifname, MAC_VAR(sta->addr));
	}
	if (sta->info)
		free(sta->info);
	sta->info = malloc(blob_pad_len(b.head));
	memcpy(sta->info, b.head, blob_pad_len(b.head));
}

static void
nl80211_del_station(struct wifi_station *sta, char *ifname)
{
	ULOG_INFO("del station %s "MAC_FMT"\n", ifname, MAC_VAR(sta->addr));
	list_del(&sta->mac);
	list_del(&sta->iface);
	avl_delete(&sta_tree, &sta->avl);
	free(sta);
}

static void
_nl80211_del_station(struct nlattr **tb, char *ifname)
{
	struct wifi_station *sta;
	uint8_t *addr;

	if (tb[NL80211_ATTR_MAC] == NULL)
		return;

	addr = nla_data(tb[NL80211_ATTR_MAC]);
	sta = avl_find_element(&sta_tree, addr, sta, avl);
	if (!sta)
		return;
	nl80211_del_station(sta, ifname);
}

struct wifi_iface*
wifi_get_interface(char *ifname)
{
	struct wifi_iface *wif;

	return avl_find_element(&wif_tree, ifname, wif, avl);
}

static void
nl80211_add_iface(struct nlattr **tb, char *ifname)
{
	struct wifi_iface *wif;
	uint8_t *addr;

	if (tb[NL80211_ATTR_MAC] == NULL)
		return;

	addr = nla_data(tb[NL80211_ATTR_MAC]);
	wif = avl_find_element(&wif_tree, ifname, wif, avl);
	if (!wif) {
		wif = malloc(sizeof(*wif));
		if (!wif)
			return;

		memset(wif, 0, sizeof(*wif));
		memcpy(wif->addr, addr, 6);
		strncpy(wif->ifname, ifname, IF_NAMESIZE);
		wif->avl.key = wif->ifname;
		wif->assoc.cb = nl80211_assoc_list;
		wif->info = NULL;
		INIT_LIST_HEAD(&wif->stas);
		nl80211_assoc_list(&wif->assoc);
		avl_insert(&wif_tree, &wif->avl);
		ULOG_INFO("new wifi %s "MAC_FMT"\n", wif->ifname, MAC_VAR(wif->addr));
			nl80211_to_blob(tb, NULL);
		memcpy(wif->addr, addr, 6);
	}
	if (wif->info)
		free(wif->info);
	wif->info = malloc(blob_pad_len(b.head));
	memcpy(wif->info, b.head, blob_pad_len(b.head));
}

static void
nl80211_del_iface(struct nlattr **tb, char *ifname)
{
	struct wifi_station *sta, *tmp;
	struct wifi_iface *wif;

	wif = avl_find_element(&wif_tree, ifname, wif, avl);
	if (!wif)
		return;
	list_for_each_entry_safe(sta, tmp, &wif->stas, iface)
		nl80211_del_station(sta, wif->ifname);
	ULOG_INFO("del wifi %s "MAC_FMT"\n", wif->ifname, MAC_VAR(wif->addr));
	avl_delete(&wif_tree, &wif->avl);
	uloop_timeout_cancel(&wif->assoc);
	free(wif);
}

static int
nl80211_get_noise_cb(struct nlattr **tb, char *ifname)
{
	struct nlattr *si[NL80211_SURVEY_INFO_MAX + 1];
	struct wifi_iface *wif;

	static struct nla_policy sp[NL80211_SURVEY_INFO_MAX + 1] = {
		[NL80211_SURVEY_INFO_FREQUENCY] = { .type = NLA_U32 },
		[NL80211_SURVEY_INFO_NOISE]     = { .type = NLA_U8  },
	};

	wif = avl_find_element(&wif_tree, ifname, wif, avl);
	if (!wif)
		return NL_SKIP;

	if (!tb[NL80211_ATTR_SURVEY_INFO])
		return NL_SKIP;

	if (nla_parse_nested(si, NL80211_SURVEY_INFO_MAX,
			     tb[NL80211_ATTR_SURVEY_INFO], sp))
		return NL_SKIP;

	if (!si[NL80211_SURVEY_INFO_NOISE])
		return NL_SKIP;

	wif->noise = 0;
	if (si[NL80211_SURVEY_INFO_IN_USE])
		wif->noise = (int8_t)nla_get_u8(si[NL80211_SURVEY_INFO_NOISE]);

	return NL_SKIP;
}
static int
nl80211_mcast_grp(struct nlattr **tb, struct family_data *res)
{
	struct nlattr *mcgrp;
	int i;

	nla_for_each_nested(mcgrp, tb[CTRL_ATTR_MCAST_GROUPS], i) {
		struct nlattr *tb2[CTRL_ATTR_MCAST_GRP_MAX + 1];

		nla_parse(tb2, CTRL_ATTR_MCAST_GRP_MAX, nla_data(mcgrp),
		nla_len(mcgrp), NULL);

		if (!tb2[CTRL_ATTR_MCAST_GRP_NAME] ||
		    !tb2[CTRL_ATTR_MCAST_GRP_ID] ||
		    strncmp(nla_data(tb2[CTRL_ATTR_MCAST_GRP_NAME]), res->group, nla_len(tb2[CTRL_ATTR_MCAST_GRP_NAME])) != 0)
			continue;
		res->id = nla_get_u32(tb2[CTRL_ATTR_MCAST_GRP_ID]);
		break;
	}

	return NL_SKIP;
}

static int
cb_nl80211_status(struct nl_msg *msg, void *arg)
{
	struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
	struct nlattr *tb[NL80211_ATTR_MAX + 1];
	char ifname[IFNAMSIZ] = {};
	int ifidx = -1;

	nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
		  genlmsg_attrlen(gnlh, 0), NULL);

	if (tb[CTRL_ATTR_MCAST_GROUPS]) {
		return nl80211_mcast_grp(tb, arg);

	} else if (tb[NL80211_ATTR_IFINDEX]) {
		ifidx = nla_get_u32(tb[NL80211_ATTR_IFINDEX]);
		if_indextoname(ifidx, ifname);

	} else if (tb[NL80211_ATTR_IFNAME]) {
	        strncpy(ifname, nla_get_string(tb[NL80211_ATTR_IFNAME]), IFNAMSIZ);

	} else
		return 0;

	switch (gnlh->cmd) {
	case NL80211_CMD_NEW_STATION:
		nl80211_add_station(tb, ifname);
		break;
	case NL80211_CMD_DEL_STATION:
		_nl80211_del_station(tb, ifname);
		break;
	case NL80211_CMD_NEW_INTERFACE:
		nl80211_add_iface(tb, ifname);
		break;
	case NL80211_CMD_DEL_INTERFACE:
		nl80211_del_iface(tb, ifname);
		break;
	case NL80211_CMD_NEW_SURVEY_RESULTS:
		nl80211_get_noise_cb(tb, ifname);
		break;
	default:
		break;
	}

	return 0;
}

static int
genl_get_multicast_id(struct nl_socket *ev,
		      const char *family, const char *group)
{
	struct nl_msg *msg;
	struct family_data *genl_res = (struct family_data *) &nl80211_arg;
	genl_res->group = group;
	genl_res->id = -ENOENT;

	msg = nlmsg_alloc();
	if (!msg)
		return -ENOMEM;
	if (!genlmsg_put(msg, 0, 0, genl_ctrl_resolve(ev->sock, "nlctrl"),
			 0, 0, CTRL_CMD_GETFAMILY, 0) ||
		nla_put_string(msg, CTRL_ATTR_FAMILY_NAME, family)) {
		nlmsg_free(msg);
		return -1;
	}

	genl_send_and_recv(ev, msg);

	return genl_res->id;
}

int nl80211_init(void)
{
	int id;

	if (!nl_status_socket(&nl80211_status, NETLINK_GENERIC, cb_nl80211_status, &nl80211_arg))
		return -1;

	id = genl_get_multicast_id(&nl80211_status, "nl80211", "config");
	if (id >= 0)
		nl_socket_add_membership(nl80211_status.sock, id);

	id = genl_get_multicast_id(&nl80211_status, "nl80211", "mlme");
	if (id >= 0)
		nl_socket_add_membership(nl80211_status.sock, id);

	id = genl_get_multicast_id(&nl80211_status, "nl80211", "vendor");
	if (id >= 0)
		nl_socket_add_membership(nl80211_status.sock, id);

	nl80211_list_wif();

	return 0;
}
