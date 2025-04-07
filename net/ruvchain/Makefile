include $(TOPDIR)/rules.mk

PKG_NAME:=ruvchain
PKG_VERSION:=0.5.12
PKG_RELEASE:=1

PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_SOURCE_URL:=https://codeload.github.com/ruvcoindev/ruvchain/tar.gz/v$(PKG_VERSION)?
PKG_HASH:=edf0286bf069d7f9762d77e1fcf3e98868e25b86b991589e980c1c9be7f01bbe
PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)

PKG_MAINTAINER:= ruvcoindev <admin@ruvcha.in>
PKG_LICENSE:=LGPL-3.0-only
PKG_LICENSE_FILES:=LICENSE

PKG_BUILD_DEPENDS:=golang/host
PKG_BUILD_PARALLEL:=1
PKG_BUILD_FLAGS:=no-mips16

GO_PKG:=github.com/ruvcoindev/ruvchain
GO_PKG_BUILD_PKG:=github.com/ruvcoindev/ruvchain/cmd/...

GO_PKG_LDFLAGS_X:= \
  github.com/ruvcoindev/ruvchain/src/version.buildName=ruvchain-openwrt \
  github.com/ruvcoindev/ruvchain/src/version.buildVersion=$(PKG_VERSION)

include $(INCLUDE_DIR)/package.mk
include ../../lang/golang/golang-package.mk

define Package/ruvchain
	SECTION:=net
	CATEGORY:=Network
	SUBMENU:=Routing and Redirection
	TITLE:=Ruvchain supports end-to-end encrypted IPv6 networks
	URL:=https://ruvcha.in
	DEPENDS:=$(GO_ARCH_DEPENDS) @IPV6 +kmod-tun
endef

define Package/ruvchain/description
 Ruvchain builds end-to-end encrypted networks with IPv6.
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
