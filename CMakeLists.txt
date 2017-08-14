cmake_minimum_required(VERSION 2.6)

PROJECT(udevmand C)
INCLUDE(GNUInstallDirs)
ADD_DEFINITIONS(-Os -ggdb -Wall -Werror --std=gnu99 -Wmissing-declarations)

SET(CMAKE_SHARED_LIBRARY_LINK_C_FLAGS "")

ADD_EXECUTABLE(udevmand main.c mac.c neigh.c ubus.c nl80211.c blob.c netlink.c bridge.c dhcp.c netifd.c ethers.c netdev.c)
TARGET_LINK_LIBRARIES(udevmand ubox ubus json-c blobmsg_json nl-tiny uci)
INSTALL(TARGETS udevmand
	RUNTIME DESTINATION ${CMAKE_INSTALL_SBINDIR}
)
