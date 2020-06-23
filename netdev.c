#include "udevmand.h"

struct avl_tree iface_tree = AVL_TREE_INIT(iface_tree, avl_strcmp, false, NULL);

struct iface_ip {
	struct list_head list;
	char ip[];
};

struct iface {
	struct avl_node avl;
	char name[IF_NAMESIZE];
	struct rtnl_link_stats stats;
	struct list_head ipv6, ipv4;
	uint8_t addr[ETH_ALEN];
};

static struct iface*
iface_find(char *name)
{
	struct iface *iface = avl_find_element(&iface_tree, name, iface, avl);

	if (iface)
		return iface;
	iface = malloc(sizeof(*iface));
	if (!iface)
		return NULL;
	memset(iface, 0, sizeof(*iface));
	iface->avl.key = strcpy(iface->name, name);
	INIT_LIST_HEAD(&iface->ipv4);
	INIT_LIST_HEAD(&iface->ipv6);
	avl_insert(&iface_tree, &iface->avl);
	return iface;
}

static void
iface_get(void)
{
	int fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
	struct ifaddrs *ifaddr, *ifa;
	int n;

	if (getifaddrs(&ifaddr) == -1) {
		ULOG_ERR("failed to getifaddrs\n");
		return;
	}

	for (ifa = ifaddr, n = 0; ifa != NULL; ifa = ifa->ifa_next, n++) {
		char host[NI_MAXHOST];
		struct iface *iface;
		int family, s;

		if (ifa->ifa_addr == NULL)
			continue;

		if ((ifa->ifa_flags & IFF_UP) == 0)
			continue;

		if (ifa->ifa_flags & IFF_LOOPBACK)
			continue;

		family = ifa->ifa_addr->sa_family;

		iface = iface_find(ifa->ifa_name);
		if (!iface)
			continue;

		if (family == AF_INET || family == AF_INET6) {
			struct iface_ip *ip;

			s = getnameinfo(ifa->ifa_addr,
					(family == AF_INET) ? sizeof(struct sockaddr_in) :
					sizeof(struct sockaddr_in6),
					host, NI_MAXHOST,
					NULL, 0, NI_NUMERICHOST);
			if (s)
				continue;
			ip = malloc(sizeof(*ip) + strlen(host) + 1);
			if (!ip)
				continue;
			strcpy(ip->ip, host);
			if (family == AF_INET)
				list_add(&ip->list, &iface->ipv4);
			else
				list_add(&ip->list, &iface->ipv6);
		} else if (family == AF_PACKET && ifa->ifa_data != NULL) {
			struct rtnl_link_stats *stats = ifa->ifa_data;
			struct ifreq s;

			memcpy(&iface->stats, stats, sizeof(*stats));
			memset(iface->addr, 0, ETH_ALEN);
			if (fd) {
				strcpy(s.ifr_name, ifa->ifa_name);
				if (!ioctl(fd, SIOCGIFHWADDR, &s))
					memcpy(iface->addr, s.ifr_addr.sa_data, ETH_ALEN);
			}
		}
	}

	freeifaddrs(ifaddr);
	if (fd)
		close(fd);
}

static void
iface_flush(void)
{
	struct iface *iface, *tmp;

	avl_for_each_element_safe(&iface_tree, iface, avl, tmp) {
		struct iface_ip *ip, *tmp;

		list_for_each_entry_safe(ip, tmp, &iface->ipv4, list) {
			list_del(&ip->list);
			free(ip);
		}

		list_for_each_entry_safe(ip, tmp, &iface->ipv6, list) {
			list_del(&ip->list);
			free(ip);
		}
		avl_delete(&iface_tree, &iface->avl);
		free(iface);
	}
}

void
iface_dump(void)
{
	struct iface *iface;

	iface_get();

	blob_buf_init(&b, 0);
	avl_for_each_element(&iface_tree, iface, avl) {
		struct wifi_iface *wif;
		struct iface_ip *ip;
		void *c, *d;

		c = blobmsg_open_table(&b, iface->name);
		blobmsg_add_mac(&b, "hwaddr", iface->addr);
		if (!list_empty(&iface->ipv4)) {
			d = blobmsg_open_array(&b, "ipv4");
			list_for_each_entry(ip, &iface->ipv4, list)
				blobmsg_add_string(&b, NULL, ip->ip);
			blobmsg_close_array(&b, d);
		}

		if (!list_empty(&iface->ipv4)) {
			d = blobmsg_open_array(&b, "ipv6");
			list_for_each_entry(ip, &iface->ipv6, list)
				blobmsg_add_string(&b, NULL, ip->ip);
			blobmsg_close_array(&b, d);
		}

		d = blobmsg_open_table(&b, "stats");
		blobmsg_add_u32(&b, "rx_packets", iface->stats.rx_packets);
		blobmsg_add_u32(&b, "tx_packets", iface->stats.tx_packets);
	        blobmsg_add_u32(&b, "rx_bytes", iface->stats.rx_bytes);
	        blobmsg_add_u32(&b, "tx_bytes", iface->stats.tx_bytes);
	        blobmsg_add_u32(&b, "rx_errors", iface->stats.rx_errors);
	        blobmsg_add_u32(&b, "tx_errors", iface->stats.tx_errors);
	        blobmsg_add_u32(&b, "rx_dropped", iface->stats.rx_dropped);
	        blobmsg_add_u32(&b, "tx_dropped", iface->stats.tx_dropped);
	        blobmsg_add_u32(&b, "multicast", iface->stats.multicast);
	        blobmsg_add_u32(&b, "collisions", iface->stats.collisions);
		blobmsg_close_table(&b, d);

		wif = wifi_get_interface(iface->name);
		if (wif) {
		        static char buf[10];

			blobmsg_add_field(&b, BLOBMSG_TYPE_TABLE, "wifi",
				blobmsg_data(wif->info), blobmsg_data_len(wif->info));
			snprintf(buf, sizeof(buf), "%d", wif->noise);
			blobmsg_add_string(&b, "noise", buf);
		}
		bridge_dump_if(iface->name);
		blobmsg_close_table(&b, c);
	}

	iface_flush();
}