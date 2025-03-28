include $(TOPDIR)/rules.mk

PKG_NAME:=ruvchain
PKG_VERSION:=0.5.12
PKG_RELEASE:=1


PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION)-$(PKG_RELEASE).tar.gz
PKG_SOURCE_URL:=https://github.com/ruvcoindev/ruvchain/archive/refs/tags/v$(PKG_VERSION)-$(PKG-RELEASE)?
PKG_HASH:=606d9755a3062c9f3435607f697c2df7586d7c1e66e80150914195af6814fa62
PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)

include $(INCLUDE_DIR)/package.mk
include $(TOPDIR)/feeds/packages/lang/golang/golang-package.mk


PKG_MAINTAINER:=ruvcoindev <admin@ruvcha.in>
PKG_LICENSE:=LGPL-3.0-only
PKG_LICENSE_FILES:=LICENSE

GO_PKG:=github.com/ruvcoindev/ruvchain
GO_PKG_BUILD_PKG:=github.com/ruvcoindev/ruvchain/cmd/...

PKG_BUILD_DEPENDS:=golang/host
PKG_BUILD_PARALLEL:=1
PKG_BUILD_FLAGS:=no-mips16


GO_PKG:=github.com/ruvcoindev/ruvchain
GO_PKG_BUILD_PKG:=github.com/ruvcoindev/ruvchain/cmd/...

GO_PKG_LDFLAGS_X:= \
  github.com/ruvcoindev/ruvchain/src/version.buildName=ruvchain-openwrt \
  github.com/ruvcoindev/ruvchain/src/version.buildVersion=$(PKG_VERSION)



define Package/ruvchain
	SECTION:=net
	CATEGORY:=Network
	SUBMENU:=Routing and Redirection
	TITLE:=Ruvchain supports end-to-end encrypted IPv6 networks
	URL:=https://ruvcha.in
	DEPENDS:=$(GO_ARCH_DEPENDS) @IPV6 +kmod-tun +libstdcpp
endef

define Package/ruvchain/description
 Ruvchain creates fully encrypted IPv6 networks.
Unlike cjdns, it employs a unique routing algorithm. This globally coordinated spanning tree uses greedy routing within a metric space.
Advanced back-pressure routing techniques enable sophisticated link aggregation for each stream. 
As a result, a single stream can utilize multiple network interfaces concurrently, significantly enhancing throughput.
endef

define Package/ruvchain/install
	$(INSTALL_DIR) \
		$(1)/lib/netifd/proto \
		$(1)/usr/sbin

	$(INSTALL_BIN) \
		$(GO_PKG_BUILD_BIN_DIR)/ruvchain \
		$(1)/usr/sbin

	$(INSTALL_BIN) \
		$(GO_PKG_BUILD_BIN_DIR)/ruvchainctl \
		$(1)/usr/sbin

	$(INSTALL_BIN) \
		./files/ruvchain.sh \
		$(1)/lib/netifd/proto
endef

$(eval $(call GoBinPackage,ruvchain))
$(eval $(call BuildPackage,ruvchain))
