include $(TOPDIR)/rules.mk


PKG_NAME:=ruvchain
PKG_VERSION:=0.5.12
PKG_RELEASE:=1


PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_SOURCE_URL:=https://codeload.github.com/ruvcoindev/ruvchain/tar.gz/v$(PKG_VERSION)?
PKG_HASH:=e60462c173b458b5d3955b87553d9ae5f1e298e265e15cfb53a07ac8b574fcc4
PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)

include $(INCLUDE_DIR)/package.mk
include $(TOPDIR)/feeds/packages/lang/golang/golang-package.mk


PKG_MAINTAINER:=ruvcoindev <admin@ruvcha.in>
PKG_LICENSE:=LGPL-3.0-only
PKG_LICENSE_FILES:=LICENSE

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
	DEPENDS:=$(GO_ARCH_DEPENDS) @IPV6 +kmod-tun +libstdcpp +libopenssl 
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
