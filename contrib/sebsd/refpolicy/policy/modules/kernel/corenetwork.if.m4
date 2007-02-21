#
# shiftn(num,list...)
#
# shift the list num times
#
define(`shiftn',`ifelse($1,0,`shift($*)',`shiftn(decr($1),shift(shift($*)))')')

########################################
#
# Network Interface generated macros 
#
########################################

define(`create_netif_interfaces',``
########################################
## <summary>
##	Send and receive TCP network traffic on the $1 interface.
## </summary>
## <param name="domain">
##	<summary>
##	The type of the process performing this action.
##	</summary>
## </param>
## <infoflow type="both" weight="10"/>
#
interface(`corenet_tcp_sendrecv_$1_if',`
	gen_require(`
		$3 $1_$2;
	')

	allow dollarsone $1_$2:netif { tcp_send tcp_recv };
')

########################################
## <summary>
##	Send UDP network traffic on the $1 interface.
## </summary>
## <param name="domain">
##	<summary>
##	The type of the process performing this action.
##	</summary>
## </param>
## <infoflow type="write" weight="10"/>
#
interface(`corenet_udp_send_$1_if',`
	gen_require(`
		$3 $1_$2;
	')

	allow dollarsone $1_$2:netif udp_send;
')

########################################
## <summary>
##	Receive UDP network traffic on the $1 interface.
## </summary>
## <param name="domain">
##	<summary>
##	The type of the process performing this action.
##	</summary>
## </param>
## <infoflow type="read" weight="10"/>
#
interface(`corenet_udp_receive_$1_if',`
	gen_require(`
		$3 $1_$2;
	')

	allow dollarsone $1_$2:netif udp_recv;
')

########################################
## <summary>
##	Send and receive UDP network traffic on the $1 interface.
## </summary>
## <param name="domain">
##	<summary>
##	The type of the process performing this action.
##	</summary>
## </param>
## <infoflow type="both" weight="10"/>
#
interface(`corenet_udp_sendrecv_$1_if',`
	corenet_udp_send_$1_if(dollarsone)
	corenet_udp_receive_$1_if(dollarsone)
')

########################################
## <summary>
##	Send raw IP packets on the $1 interface.
## </summary>
## <param name="domain">
##	<summary>
##	The type of the process performing this action.
##	</summary>
## </param>
## <infoflow type="write" weight="10"/>
#
interface(`corenet_raw_send_$1_if',`
	gen_require(`
		$3 $1_$2;
	')

	allow dollarsone $1_$2:netif rawip_send;

	# cjp: comment out until raw access is
	# is fixed for network users
	#allow dollarsone self:capability net_raw;
')

########################################
## <summary>
##	Receive raw IP packets on the $1 interface.
## </summary>
## <param name="domain">
##	<summary>
##	The type of the process performing this action.
##	</summary>
## </param>
## <infoflow type="read" weight="10"/>
#
interface(`corenet_raw_receive_$1_if',`
	gen_require(`
		$3 $1_$2;
	')

	allow dollarsone $1_$2:netif rawip_recv;
')

########################################
## <summary>
##	Send and receive raw IP packets on the $1 interface.
## </summary>
## <param name="domain">
##	<summary>
##	The type of the process performing this action.
##	</summary>
## </param>
## <infoflow type="both" weight="10"/>
#
interface(`corenet_raw_sendrecv_$1_if',`
	corenet_raw_send_$1(dollarsone)
	corenet_raw_receive_$1(dollarsone)
')
'') dnl end create_netif_interfaces

########################################
#
# Network node generated macros 
#
########################################

define(`create_node_interfaces',``
########################################
## <summary>
##	Send and receive TCP traffic on the $1 node.
## </summary>
## <param name="domain">
##	<summary>
##	The type of the process performing this action.
##	</summary>
## </param>
## <infoflow type="both" weight="10"/>
#
interface(`corenet_tcp_sendrecv_$1_node',`
	gen_require(`
		$3 $1_$2;
	')

	allow dollarsone $1_$2:node { tcp_send tcp_recv };
')

########################################
## <summary>
##	Send UDP traffic on the $1 node.
## </summary>
## <param name="domain">
##	<summary>
##	The type of the process performing this action.
##	</summary>
## </param>
## <infoflow type="write" weight="10"/>
#
interface(`corenet_udp_send_$1_node',`
	gen_require(`
		$3 $1_$2;
	')

	allow dollarsone $1_$2:node udp_send;
')

########################################
## <summary>
##	Receive UDP traffic on the $1 node.
## </summary>
## <param name="domain">
##	<summary>
##	The type of the process performing this action.
##	</summary>
## </param>
## <infoflow type="read" weight="10"/>
#
interface(`corenet_udp_receive_$1_node',`
	gen_require(`
		$3 $1_$2;
	')

	allow dollarsone $1_$2:node udp_recv;
')

########################################
## <summary>
##	Send and receive UDP traffic on the $1 node.
## </summary>
## <param name="domain">
##	<summary>
##	The type of the process performing this action.
##	</summary>
## </param>
## <infoflow type="both" weight="10"/>
#
interface(`corenet_udp_sendrecv_$1_node',`
	corenet_udp_send_$1_node(dollarsone)
	corenet_udp_receive_$1_node(dollarsone)
')

########################################
## <summary>
##	Send raw IP packets on the $1 node.
## </summary>
## <param name="domain">
##	<summary>
##	The type of the process performing this action.
##	</summary>
## </param>
## <infoflow type="write" weight="10"/>
#
interface(`corenet_raw_send_$1_node',`
	gen_require(`
		$3 $1_$2;
	')

	allow dollarsone $1_$2:node rawip_send;
')

########################################
## <summary>
##	Receive raw IP packets on the $1 node.
## </summary>
## <param name="domain">
##	<summary>
##	The type of the process performing this action.
##	</summary>
## </param>
## <infoflow type="write" weight="10"/>
#
interface(`corenet_raw_receive_$1_node',`
	gen_require(`
		$3 $1_$2;
	')

	allow dollarsone $1_$2:node rawip_recv;
')

########################################
## <summary>
##	Send and receive raw IP packets on the $1 node.
## </summary>
## <param name="domain">
##	<summary>
##	The type of the process performing this action.
##	</summary>
## </param>
## <infoflow type="both" weight="10"/>
#
interface(`corenet_raw_sendrecv_$1_node',`
	corenet_raw_send_$1_node(dollarsone)
	corenet_raw_receive_$1_node(dollarsone)
')

########################################
## <summary>
##	Bind TCP sockets to node $1.
## </summary>
## <param name="domain">
##	<summary>
##	The type of the process performing this action.
##	</summary>
## </param>
## <infoflow type="none"/>
#
interface(`corenet_tcp_bind_$1_node',`
	gen_require(`
		$3 $1_$2;
	')

	allow dollarsone $1_$2:tcp_socket node_bind;
')

########################################
## <summary>
##	Bind UDP sockets to the $1 node.
## </summary>
## <param name="domain">
##	<summary>
##	The type of the process performing this action.
##	</summary>
## </param>
## <infoflow type="none"/>
#
interface(`corenet_udp_bind_$1_node',`
	gen_require(`
		$3 $1_$2;
	')

	allow dollarsone $1_$2:udp_socket node_bind;
')
'') dnl end create_node_interfaces

########################################
#
# Network port generated macros 
#
########################################

define(`create_port_interfaces',``
########################################
## <summary>
##	Send and receive TCP traffic on the $1 port.
## </summary>
## <param name="domain">
##	<summary>
##	The type of the process performing this action.
##	</summary>
## </param>
## <infoflow type="both" weight="10"/>
#
interface(`corenet_tcp_sendrecv_$1_port',`
	gen_require(`
		$3 $1_$2;
	')

	allow dollarsone $1_$2:tcp_socket { send_msg recv_msg };
')

########################################
## <summary>
##	Send UDP traffic on the $1 port.
## </summary>
## <param name="domain">
##	<summary>
##	The type of the process performing this action.
##	</summary>
## </param>
## <infoflow type="write" weight="10"/>
#
interface(`corenet_udp_send_$1_port',`
	gen_require(`
		$3 $1_$2;
	')

	allow dollarsone $1_$2:udp_socket send_msg;
')

########################################
## <summary>
##	Receive UDP traffic on the $1 port.
## </summary>
## <param name="domain">
##	<summary>
##	The type of the process performing this action.
##	</summary>
## </param>
## <infoflow type="read" weight="10"/>
#
interface(`corenet_udp_receive_$1_port',`
	gen_require(`
		$3 $1_$2;
	')

	allow dollarsone $1_$2:udp_socket recv_msg;
')

########################################
## <summary>
##	Send and receive UDP traffic on the $1 port.
## </summary>
## <param name="domain">
##	<summary>
##	The type of the process performing this action.
##	</summary>
## </param>
## <infoflow type="both" weight="10"/>
#
interface(`corenet_udp_sendrecv_$1_port',`
	corenet_udp_send_$1_port(dollarsone)
	corenet_udp_receive_$1_port(dollarsone)
')

########################################
## <summary>
##	Bind TCP sockets to the $1 port.
## </summary>
## <param name="domain">
##	<summary>
##	The type of the process performing this action.
##	</summary>
## </param>
## <infoflow type="none"/>
#
interface(`corenet_tcp_bind_$1_port',`
	gen_require(`
		$3 $1_$2;
	')

	allow dollarsone $1_$2:tcp_socket name_bind;
	$4
')

########################################
## <summary>
##	Bind UDP sockets to the $1 port.
## </summary>
## <param name="domain">
##	<summary>
##	The type of the process performing this action.
##	</summary>
## </param>
## <infoflow type="none"/>
#
interface(`corenet_udp_bind_$1_port',`
	gen_require(`
		$3 $1_$2;
	')

	allow dollarsone $1_$2:udp_socket name_bind;
	$4
')

########################################
## <summary>
##	Make a TCP connection to the $1 port.
## </summary>
## <param name="domain">
##	<summary>
##	The type of the process performing this action.
##	</summary>
## </param>
#
interface(`corenet_tcp_connect_$1_port',`
	gen_require(`
		$3 $1_$2;
	')

	allow dollarsone $1_$2:tcp_socket name_connect;
')
'') dnl end create_port_interfaces

#
# create_netif_*_interfaces(linux_interfacename)
#
define(`create_netif_type_interfaces',`
create_netif_interfaces($1,netif_t,type)
')
define(`create_netif_attrib_interfaces',`
create_netif_interfaces($1,netif,attribute)
')

#
# network_interface(linux_interfacename,mls_sensitivity)
#
define(`network_interface',`
create_netif_type_interfaces($1)
')

#
# create_node_*_interfaces(node_name)
#
define(`create_node_type_interfaces',`
create_node_interfaces($1,node_t,type)
')
define(`create_node_attrib_interfaces',`
create_node_interfaces($1,node,attribute)
')

#
# network_node(node_name,mls_sensitivity,address,netmask)
#
define(`network_node',`
create_node_type_interfaces($1)
')

# These next three macros have formatting, and should not me indented
define(`determine_reserved_capability',`dnl
ifelse($2,`',`',`dnl
ifelse(eval($2 < 1024),1,``allow' dollarsone self:capability net_bind_service;',`dnl
determine_reserved_capability(shiftn(3,$*))dnl
')dnl end inner ifelse
')dnl end outer ifelse
') dnl end determine reserved capability

#
# create_port_*_interfaces(port_name, protocol,portnum,mls_sensitivity [,protocol portnum mls_sensitivity[,...]])
# (these wrap create_port_interfaces to handle attributes and types)
define(`create_port_type_interfaces',`create_port_interfaces($1,port_t,type,determine_reserved_capability(shift($*)))')
define(`create_port_attrib_interfaces',`create_port_interfaces($1,port,attribute,determine_reserved_capability(shift($*)))')

#
# network_port(port_name,protocol portnum mls_sensitivity [,protocol,portnum,mls_sensitivity[,...]])
#
define(`network_port',`
create_port_type_interfaces($*)
')
