#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <glob.h>
#include <time.h>
#include <ifaddrs.h>

#include <net/if.h>

#include <sys/ioctl.h>
#include <sys/types.h>

#include <linux/if_ether.h>
#include <linux/rtnetlink.h>
#include <linux/nl80211.h>
#include <linux/limits.h>
#include <linux/sockios.h>
#include <linux/ethtool.h>

#include <netlink/msg.h>
#include <netlink/attr.h>
#include <netlink/socket.h>
#include <netlink/genl/ctrl.h>
#include <netlink/genl/genl.h>

#include <libubox/avl.h>
#include <libubox/avl-cmp.h>
#include <libubox/uloop.h>
#include <libubox/utils.h>
#include <libubox/ulog.h>
#include <libubox/blobmsg_json.h>
#include <libubox/vlist.h>

#include <libubus.h>

#define MAC_FMT	"%02x:%02x:%02x:%02x:%02x:%02x"
#define MAC_VAR(x) x[0], x[1], x[2], x[3], x[4], x[5]

#define IP_FMT	"%d.%d.%d.%d"
#define IP_VAR(x) x[0], x[1], x[2], x[3]

struct nl_socket {
	struct uloop_fd uloop;
	struct nl_sock *sock;
	int bufsize;
};

struct mac {
	uint8_t *addr;
	struct avl_node avl;
	char interface[64];
	char *ethers;

	struct timespec ts;
	struct list_head neigh4;
	struct list_head neigh6;
	struct list_head wifi;
	struct list_head dhcpv4;
	struct list_head bridge_mac;
};

struct neigh {
	struct avl_node avl;
	struct list_head list;

	uint8_t *ip;
	int ip_ver;
	int iface;
	char ifname[IF_NAMESIZE];

	struct uloop_timeout ageing;
};

struct wifi_iface {
	struct avl_node avl;
	uint8_t addr[6];

	struct blob_attr *info;
	int noise;

	char ifname[IF_NAMESIZE];
	struct list_head stas;
	struct uloop_timeout assoc;
};

struct wifi_station {
	struct avl_node avl;
	uint8_t addr[6];

	struct blob_attr *info;

	struct wifi_iface *wif;
	struct list_head mac;
	struct list_head iface;
};

struct dhcpv4 {
	struct avl_node avl;
	struct list_head mac;

	uint8_t addr[ETH_ALEN];
	uint8_t ip[4];
	char iface[IF_NAMESIZE];
	char name[];
};

struct interface {
	struct avl_node avl;

	char *iface;
	char *device;
};

struct bridge_mac {
	struct vlist_node vlist;
	struct list_head mac;

	char bridge[IF_NAMESIZE];
	char ifname[IF_NAMESIZE];
	uint8_t addr[ETH_ALEN];
	__u8 port_no;
};

extern int avl_mac_cmp(const void *k1, const void *k2, void *ptr);

extern struct avl_tree mac_tree;
extern int mac_dump_all(void);
extern void mac_dump(struct mac *mac, int interface);
extern struct mac* mac_find(uint8_t *addr);
extern void mac_update(struct mac *mac, char *iface);

extern int neigh_init(void);
extern void neigh_enum(void);

extern bool nl_status_socket(struct nl_socket *ev, int protocol,
			     int (*cb)(struct nl_msg *msg, void *arg), void *priv);
extern int genl_send_and_recv(struct nl_socket *ev, struct nl_msg * msg);

extern int nl80211_init(void);
extern void nl80211_enum(void);

extern struct blob_buf b;
extern void blobmsg_add_iface(struct blob_buf *bbuf, char *name, int index);
extern void blobmsg_add_iftype(struct blob_buf *bbuf, const char *name, const uint32_t iftype);
extern void blobmsg_add_ipv4(struct blob_buf *bbuf, const char *name, const uint8_t* addr);
extern void blobmsg_add_ipv6(struct blob_buf *bbuf, const char *name, const uint8_t* addr);
extern void blobmsg_add_mac(struct blob_buf *bbuf, const char *name, const uint8_t* addr);

extern void ubus_init(void);
extern void ubus_uninit(void);

extern void bridge_init(void);
extern void bridge_dump_if(const char *bridge);

extern void dhcpv4_ack(struct blob_attr *msg);
extern void dhcpv4_release(struct blob_attr *msg);
extern void dhcp_init(void);

extern int interface_dump(void);
extern void interface_update(struct blob_attr *msg, int raw);
extern void interface_down(struct blob_attr *msg);
extern char *interface_resolve(char *device);

extern void ethers_init(void);

extern void iface_dump(void);

extern struct wifi_iface *wifi_get_interface(char *name);
