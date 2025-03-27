#!/bin/sh


[ -n "$INCLUDE_ONLY" ] || {
	. /lib/functions.sh
	. ../netifd-proto.sh
	init_proto "$@"
}

proto_ruvchain_init_config() {
	available=1

	# Ruvchain
	proto_config_add_string "private_key"
	proto_config_add_boolean "allocate_listen_addresses"

	# Connector
	proto_config_add_boolean "connector_enable"
	proto_config_add_string "connector_loglevel"
	proto_config_add_boolean "connector_autofill_listen_addresses"
	proto_config_add_string "connector_config"
}

proto_ruvchain_setup_peer_if_non_interface() {
	local peer_config="$1"
	local peer_address
	local peer_interface
	config_get peer_address "${peer_config}" "address"
	config_get peer_interface "${peer_config}" "interface"
	if [ -z ${peer_interface} ]; then
		json_add_string "" ${peer_address}
	fi;
}

proto_ruvchain_dump_peer_interface() {
	local peer_config="$1"
	local peer_interface

	config_get peer_interface "${peer_config}" "interface"

	if [ ! -z ${peer_interface} ]; then
		peer_interfaces="${peer_interfaces}\n${peer_interface}"
	fi;
}

proto_ruvchain_setup_peer_if_interface() {
	local peer_config="$1"
	local peer_address
	local peer_interface
	config_get peer_interface "${peer_config}" "interface"
	if [ "${peer_interface}" = "${peer_interface_filter}" ]; then
		config_get peer_address "${peer_config}" "address"
		json_add_string "" ${peer_address}
	fi;
}

proto_ruvchain_append_to_interface_regex() {
	if [ -z "${regex}" ]; then
		regex="$1"
	else
		regex="${regex}|$1";
	fi;
}

proto_ruvchain_setup_multicast_interface() {
	local interface_config="$1"
	local beacon
	local listen
	local port=0
	local password
	local regex=""

	config_get beacon "${interface_config}" "beacon"
	config_get listen "${interface_config}" "listen"
	config_get port "${interface_config}" "port"
	config_get password "${interface_config}" "password"

	json_add_object ""
	json_add_boolean "Beacon" $beacon
	json_add_boolean "Listen" $listen
	if [ ! -z ${port} ]; then
		json_add_int "Port" $port
	else
		json_add_int "Port" 0
	fi;
	if [ ! -z ${password} ]; then
		json_add_string "Password" $password
	fi;

	config_list_foreach "${interface_config}" interface proto_ruvchain_append_to_interface_regex

	json_add_string "Regex" "^(${regex})\$"

	json_close_object
}

proto_ruvchain_add_string() {
	json_add_string "" $1
}

proto_ruvchain_generate_keypair() {
	json_load "$(ruvchain -genconf -json)"
	json_get_vars PrivateKey
	json_cleanup
	private_key=$PrivateKey
	public_key=${PrivateKey:64}
}

proto_ruvchain_allocate_listen_addresses() {
	local config="$1"

	# Collect already defined protocols
	protocols=""
	_add_address_protocol() {
		protocols="${protocols}$(echo $1 | cut -d "://" -f1) "
	}
	config_list_foreach "$config" listen_address _add_address_protocol

	# Add new address for each previously unspecified protocol
	for protocol in "tls" "quic"; do
		if ! echo "$protocols" | grep "$protocol" &>/dev/null; then
			# By default linux dynamically alocates ports in the range 32768..60999
			# `sysctl net.ipv4.ip_local_port_range`
			random_port=$(( ($RANDOM + $RANDOM) % 22767 + 10000 ))
			proto_ruvchain_add_string "${protocol}://127.0.0.1:${random_port}"
		fi
	done
}

proto_ruvchain_generate_connector_config() {
	local config="$1"
	local ruvchain_sock="$2"
	local ruvchain_cfg="$3"

	# Autofill Ruvchain listeners
	config_get is_autofill_listeners "$config" "connector_autofill_listen_addresses"
	if [ "$is_autofill_listeners" == "1" ]; then
		echo "ruvchain_listen = ["
		_print_address() {
			echo "\"${1}\","
		}
		json_load_file "${ruvchain_cfg}"
		json_for_each_item _print_address "Listen"
		echo "]"
	fi

	# Print admin api socket
	echo "ruvchain_admin_listen = [ \"${ruvchain_sock}\" ]"

	# Print extra config
	config_get connector_config "$config" "connector_config"
	echo "${connector_config}"
}

proto_ruvchain_setup() {
	local config="$1"
	local device="$2"
	local ruvchain_dir="/tmp/ruvchain"
	local ruvchain_cfg="${ruvchain_dir}/${config}.conf"
	local ruvchain_sock="unix://${ruvchain_dir}/${config}.sock"


	local private_key
	local public_key
	local mtu
	local listen_addresses
	local whitelisted_keys
	local node_info
	local node_info_privacy

	config_load network
	config_get private_key "${config}" "private_key"
	config_get public_key "${config}" "public_key"
	config_get mtu "${config}" "mtu"
	config_get node_info "${config}" "node_info"
	config_get node_info_privacy "${config}" "node_info_privacy"

	if [ -z $private_key ]; then
		proto_ruvchain_generate_keypair
	fi;

	umask 077
	mkdir -p "${ruvchain_dir}"

	if [ $private_key = "auto" ]; then
		proto_ruvchain_generate_keypair
		uci -t ${ruvchain_dir}/.uci.${config} batch <<EOF
			set network.${config}.private_key='${private_key}'
			set network.${config}.public_key='${public_key}'
EOF
		uci -t ${ruvchain_dir}/.uci.${config} commit;
	fi;

	# Generate config file
	json_init
	json_add_string "IfName" ${config}
	json_add_string "AdminListen" ${ruvchain_sock}

	json_add_string "PrivateKey" ${private_key}
	json_add_string "PublicKey" ${public_key}

	if [ ! -z $mtu ]; then
		json_add_int "IfMTU" ${mtu}
	fi;

	if [ ! -z $node_info ]; then
		json_add_string "NodeInfo" "%%_RUVCHAIN_NODEINFO_TEMPLATE_%%"
	fi;

	json_add_boolean "NodeInfoPrivacy" ${node_info_privacy}

	# Peers
	json_add_array "Peers"
	config_foreach proto_ruvchain_setup_peer_if_non_interface "ruvchain_${config}_peer"
	json_close_array

	local peer_interfaces
	peer_interfaces=""
	config_foreach proto_ruvchain_dump_peer_interface "ruvchain_${config}_peer"
	peer_interfaces=$(echo -e ${peer_interfaces} | sort | uniq)

	json_add_object "InterfacePeers"
	for peer_interface_filter in ${peer_interfaces}; do
		json_add_array "${peer_interface_filter}"
		config_foreach proto_ruvchain_setup_peer_if_interface "ruvchain_${config}_peer"
		json_close_array
	done
	json_close_object

	json_add_array "AllowedPublicKeys"
	config_list_foreach "$config" allowed_public_key proto_ruvchain_add_string
	json_close_array

	json_add_array "Listen"
	config_list_foreach "$config" listen_address proto_ruvchain_add_string

	# If needed, add new address for each previously unspecified protocol
	config_get is_connector_enabled "$config" "connector_enable"
	config_get allocate_listen_addresses "$config" "allocate_listen_addresses"
	if [ "$is_connector_enabled" == "1" ] && [ "$allocate_listen_addresses" == "1" ]; then
		proto_ruvchain_allocate_listen_addresses "$config"
	fi

	json_close_array

	json_add_array "MulticastInterfaces"
	config_foreach proto_ruvchain_setup_multicast_interface "ruvchain_${config}_interface"
	json_close_array

	json_dump > "${ruvchain_cfg}.1"
	awk -v s='"%%_RUVCHAIN_NODEINFO_TEMPLATE_%%"' -v r="${node_info}" '{gsub(s, r)} 1' "${ruvchain_cfg}.1" > ${ruvchain_cfg}
	rm "${ruvchain_cfg}.1"

	proto_run_command "$config" /usr/sbin/ruvchain -useconffile "${ruvchain_cfg}"
	proto_init_update "$config" 1
	proto_add_ipv6_address "$(ruvchain -useconffile "${ruvchain_cfg}" -address)" "7"
	proto_add_ipv6_prefix "$(ruvchain -useconffile "${ruvchain_cfg}" -subnet)"
	proto_send_update "$config"

	# Start connector if needed
	config_get is_connector_enabled "$config" "connector_enable"
	if [ "$is_connector_enabled" == "1" ] && [ -f /usr/sbin/ruvchain-connector ]; then
		connector_cfg="${ruvchain_dir}/${config}-connector.conf"
		proto_ruvchain_generate_connector_config "$config" "$ruvchain_sock" "$ruvchain_cfg" > "$connector_cfg"

		config_get connector_loglevel "$config" "connector_loglevel"
		sh -c "sleep 2 && exec /usr/sbin/ruvchain-connector --loglevel \"${connector_loglevel:-info}\" --config \"$connector_cfg\" 2&>1 | logger -t \"${config}-connector\"" &
	fi
}

proto_ruvchain_teardown() {
	local interface="$1"
	proto_kill_command "$interface"
}

[ -n "$INCLUDE_ONLY" ] || {
	add_protocol ruvchain
}
