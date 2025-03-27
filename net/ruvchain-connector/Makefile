include $(TOPDIR)/rules.mk

PKG_NAME:=ruvchain-connector
PKG_VERSION:=0.1.1
PKG_RELEASE:=1

PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_SOURCE_URL:=https://codeload.github.com/ruvcoindev/ruvchain-connector/tar.gz/v$(PKG_VERSION)?
PKG_HASH:=7ba5c4ad299a011f2155c9f00b98a8dd548dd0868d1d0328047f139ad02bfb7c


PKG_MAINTAINER:=ruvcoindev <admin@ruvcha.in>
PKG_LICENSE:=LGPL-3.0-only
PKG_LICENSE_FILES:=LICENSE

PKG_BUILD_DEPENDS:=rust/host
PKG_BUILD_PARALLEL:=1

include $(INCLUDE_DIR)/package.mk
include ../../lang/rust/rust-package.mk

define Package/ruvchain-connector
  SECTION:=net
  CATEGORY:=Network
  SUBMENU:=Routing and Redirection
  TITLE:=Ruvchain peer-to-peer firewall stun
  URL:=https://github.com/ruvcoindev/ruvchain-connector
  DEPENDS:=$(RUST_ARCH_DEPENDS) @!arc @IPV6 +kmod-tun 
endef

define Package/ruvchain-connector/description
  Ruvchain-connector is an independent project that aims to transparently reduce
  latency of a connection over Ruvchain network, utilizing NAT traversal to
  bypass intermediary nodes. It periodically probes for active sessions and
  automatically establishes direct peerings over internet with remote nodes
  running Ruvchain-connector without requiring any firewall configuration or
  port mapping.
endef

define Package/ruvchain-connector/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/bin/ruvchain-connector $(1)/usr/sbin
endef

$(eval $(call RustBinPackage,ruvchain-connector))
$(eval $(call BuildPackage,ruvchain-connector))
