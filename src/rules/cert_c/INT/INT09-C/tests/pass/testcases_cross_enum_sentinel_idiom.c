/*
 * Rule: INT09-C
 * Status: PASS - cross-enum MAX-sentinel idiom (hostap/QCA netlink-attribute
 * header style, task 453 follow-up): a nested attribute enum's MAX bound
 * references a *different* enum's member (the containing attribute's own
 * value) rather than a same-enum sentinel. Just as unambiguously intentional
 * as `violet = indigo` within a single enum.
 */

enum qca_wlan_vendor_attr_mbssid_tx_vdev_status {
	QCA_WLAN_VENDOR_ATTR_MBSSID_TX_VDEV_STATUS_INVALID = 0,
	QCA_WLAN_VENDOR_ATTR_MBSSID_TX_VDEV_STATUS_VAL = 1,
	QCA_WLAN_VENDOR_ATTR_MBSSID_TX_VDEV_EVENT = 2,
	QCA_WLAN_VENDOR_ATTR_MBSSID_TX_VDEV_GROUP_ID = 3,
	QCA_WLAN_VENDOR_ATTR_MBSSID_TX_VDEV_GROUP_INFO = 4,
};

enum qca_wlan_vendor_attr_mbssid_tx_vdev_group_info {
	QCA_WLAN_VENDOR_ATTR_MBSSID_TX_VDEV_GROUP_INFO_INVALID = 0,
	QCA_WLAN_VENDOR_ATTR_MBSSID_TX_VDEV_GROUP_INFO_IF_INDEX = 1,
	QCA_WLAN_VENDOR_ATTR_MBSSID_TX_VDEV_GROUP_INFO_STATUS = 2,

	QCA_WLAN_VENDOR_ATTR_MBSSID_TX_VDEV_GROUP_INFO_AFTER_LAST,
	QCA_WLAN_VENDOR_ATTR_MBSSID_TX_VDEV_GROUP_INFO_MAX =
	QCA_WLAN_VENDOR_ATTR_MBSSID_TX_VDEV_GROUP_INFO - 1,
};
