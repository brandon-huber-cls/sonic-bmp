#include "EVPN.h"

namespace bgp_msg {

    /**
     * Constructor for class
     *
     * \details Handles bgp Extended Communities
     *
     * \param [in]     logPtr       Pointer to existing Logger for app logging
     * \param [in]     peerAddr     Printed form of peer address used for logging
     * \param [in]     isUnreach    True if MP UNREACH, false if MP REACH
     * \param [out]    parsed_data  Reference to parsed_update_data; will be updated with all parsed data

     * \param [in]     enable_debug Debug true to enable, false to disable
     */
    EVPN::EVPN(Logger *logPtr, std::string peerAddr, bool isUnreach,
               UpdateMsg::parsed_update_data *parsed_data, bool enable_debug) {
        logger = logPtr;
        debug = enable_debug;
        peer_addr = peerAddr;
        this->parsed_data = parsed_data;
        this->isUnreach = isUnreach;
    }

    EVPN::~EVPN() {
    }

    /**
     * Parse Ethernet Segment Identifier
     *
     * \details
     *      Will parse the Segment Identifier. Based on https://tools.ietf.org/html/rfc7432#section-5
     *
     * \param [in]      data_pointer  Pointer to the beginning of Ethernet Segment Identifier
     * \param [in]      remaining_len Remaining bytes available in the buffer
     * \param [out]     parsed_data   Reference to string where parsed data will be stored
     * \param [out]     bytes_read    Number of bytes consumed from the buffer
     * 
     * \return true if parsing succeeded, false if buffer is too short
     */
    bool EVPN::parseEthernetSegmentIdentifier(u_char *data_pointer, size_t remaining_len, 
                                               std::string *parsed_data, size_t *bytes_read) {
        std::stringstream result;
        
        // Need at least 1 byte for type
        if (remaining_len < 1) {
            LOG_WARN("%s: Insufficient data for ESI type (need 1, have %zu)", peer_addr.c_str(), remaining_len);
            return false;
        }
        
        uint8_t type = *data_pointer;
        data_pointer++;
        remaining_len--;
        *bytes_read = 1;

        result << (int) type << " ";

        switch (type) {
            case 0: {
                // Need 9 bytes for type 0
                if (remaining_len < 9) {
                    LOG_WARN("%s: Insufficient data for ESI type 0 (need 9, have %zu)", peer_addr.c_str(), remaining_len);
                    return false;
                }
                for (int i = 0; i < 9; i++) {
                    result << std::hex << setfill('0') << setw(2) << (int) data_pointer[i];
                }
                *bytes_read += 9;
                break;
            }
            case 1: {
                // Need 6 bytes for MAC + 2 bytes for port key
                if (remaining_len < 8) {
                    LOG_WARN("%s: Insufficient data for ESI type 1 (need 8, have %zu)", peer_addr.c_str(), remaining_len);
                    return false;
                }
                for (int i = 0; i < 6; ++i) {
                    if (i != 0) result << ':';
                    result.width(2);
                    result.fill('0');
                    result << std::hex << (int) (data_pointer[i]);
                }
                data_pointer += 6;

                result << " ";

                uint16_t CE_LACP_port_key;
                memcpy(&CE_LACP_port_key, data_pointer, 2);
                bgp::SWAP_BYTES(&CE_LACP_port_key, 2);

                result << std::dec << (int) CE_LACP_port_key;
                *bytes_read += 8;
                break;
            }
            case 2: {
                // Need 6 bytes for MAC + 2 bytes for priority
                if (remaining_len < 8) {
                    LOG_WARN("%s: Insufficient data for ESI type 2 (need 8, have %zu)", peer_addr.c_str(), remaining_len);
                    return false;
                }
                for (int i = 0; i < 6; ++i) {
                    if (i != 0) result << ':';
                    result.width(2);
                    result.fill('0');
                    result << std::hex << (int) (data_pointer[i]);
                }
                data_pointer += 6;

                result << " ";

                uint16_t root_bridge_priority;
                memcpy(&root_bridge_priority, data_pointer, 2);
                bgp::SWAP_BYTES(&root_bridge_priority, 2);

                result << std::dec << (int) root_bridge_priority;
                *bytes_read += 8;
                break;
            }
            case 3: {
                // Need 6 bytes for MAC + 3 bytes for discriminator
                if (remaining_len < 9) {
                    LOG_WARN("%s: Insufficient data for ESI type 3 (need 9, have %zu)", peer_addr.c_str(), remaining_len);
                    return false;
                }
                for (int i = 0; i < 6; ++i) {
                    if (i != 0) result << ':';
                    result.width(2);
                    result.fill('0');
                    result << std::hex << (int) (data_pointer[i]);
                }
                data_pointer += 6;

                result << " ";

                uint32_t local_discriminator_value;
                memcpy(&local_discriminator_value, data_pointer, 3);
                bgp::SWAP_BYTES(&local_discriminator_value, 4);
                local_discriminator_value = local_discriminator_value >> 8;
                result << std::dec << (int) local_discriminator_value;
                *bytes_read += 9;
                break;
            }
            case 4: {
                // Need 4 bytes for router ID + 4 bytes for discriminator
                if (remaining_len < 8) {
                    LOG_WARN("%s: Insufficient data for ESI type 4 (need 8, have %zu)", peer_addr.c_str(), remaining_len);
                    return false;
                }
                uint32_t router_id;
                memcpy(&router_id, data_pointer, 4);
                bgp::SWAP_BYTES(&router_id, 4);
                result << std::dec << (int) router_id << " ";

                data_pointer += 4;

                uint32_t local_discriminator_value;
                memcpy(&local_discriminator_value, data_pointer, 4);
                bgp::SWAP_BYTES(&local_discriminator_value, 4);
                result << std::dec << (int) local_discriminator_value;
                *bytes_read += 8;
                break;
            }
            case 5: {
                // Need 4 bytes for AS number + 4 bytes for discriminator
                if (remaining_len < 8) {
                    LOG_WARN("%s: Insufficient data for ESI type 5 (need 8, have %zu)", peer_addr.c_str(), remaining_len);
                    return false;
                }
                uint32_t as_number;
                memcpy(&as_number, data_pointer, 4);
                bgp::SWAP_BYTES(&as_number, 4);
                result << std::dec << (int) as_number << " ";

                data_pointer += 4;

                uint32_t local_discriminator_value;
                memcpy(&local_discriminator_value, data_pointer, 4);
                bgp::SWAP_BYTES(&local_discriminator_value, 4);
                result << std::dec << (int) local_discriminator_value;
                *bytes_read += 8;
                break;
            }
            default:
                LOG_WARN("%s: MP_REACH Cannot parse ethernet segment identifier type: %d", peer_addr.c_str(), type);
                return false;
        }

        *parsed_data = result.str();
        return true;
    }

    /**
     * Parse Route Distinguisher
     *
     * \details
     *      Will parse the Route Distinguisher. Based on https://tools.ietf.org/html/rfc4364#section-4.2
     *
     * \param [in]      data_pointer               Pointer to the beginning of Route Distinguisher
     * \param [in]      remaining_len              Remaining bytes available in the buffer
     * \param [out]     rd_type                    Reference to RD type.
     * \param [out]     rd_assigned_number         Reference to Assigned Number subfield
     * \param [out]     rd_administrator_subfield  Reference to Administrator subfield
     * 
     * \return true if parsing succeeded, false if buffer is too short
     */
    bool EVPN::parseRouteDistinguisher(u_char *data_pointer, size_t remaining_len, uint8_t *rd_type, 
                                       std::string *rd_assigned_number, std::string *rd_administrator_subfield) {
        std::stringstream   val_ss;

        // Need at least 8 bytes for RD (2 bytes type + 6 bytes value)
        if (remaining_len < 8) {
            LOG_WARN("%s: Insufficient data for Route Distinguisher (need 8, have %zu)", peer_addr.c_str(), remaining_len);
            return false;
        }

        data_pointer++;
        *rd_type = *data_pointer;
        data_pointer++;

        switch (*rd_type) {
            case 0: {
                uint16_t administration_subfield;
                bzero(&administration_subfield, 2);
                memcpy(&administration_subfield, data_pointer, 2);

                data_pointer += 2;

                uint32_t assigned_number_subfield;
                bzero(&assigned_number_subfield, 4);
                memcpy(&assigned_number_subfield, data_pointer, 4);

                bgp::SWAP_BYTES(&administration_subfield);
                bgp::SWAP_BYTES(&assigned_number_subfield);

                val_ss << assigned_number_subfield;

                *rd_assigned_number = val_ss.str();

                val_ss.str("");
                val_ss.clear();
                val_ss << administration_subfield;
                *rd_administrator_subfield = val_ss.str();

                break;
            };

            case 1: {
                u_char administration_subfield[4];
                bzero(&administration_subfield, 4);
                memcpy(&administration_subfield, data_pointer, 4);

                data_pointer += 4;

                uint16_t assigned_number_subfield;
                bzero(&assigned_number_subfield, 2);
                memcpy(&assigned_number_subfield, data_pointer, 2);

                bgp::SWAP_BYTES(&assigned_number_subfield);

                char administration_subfield_chars[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, administration_subfield, administration_subfield_chars, INET_ADDRSTRLEN);

                val_ss << assigned_number_subfield;
                *rd_assigned_number = val_ss.str();

                *rd_administrator_subfield = administration_subfield_chars;

                break;
            };

            case 2: {
                uint32_t administration_subfield;
                bzero(&administration_subfield, 4);
                memcpy(&administration_subfield, data_pointer, 4);

                data_pointer += 4;

                uint16_t assigned_number_subfield;
                bzero(&assigned_number_subfield, 2);
                memcpy(&assigned_number_subfield, data_pointer, 2);

                bgp::SWAP_BYTES(&administration_subfield);
                bgp::SWAP_BYTES(&assigned_number_subfield);

                val_ss << assigned_number_subfield;
                *rd_assigned_number = val_ss.str();

                val_ss.str("");
                val_ss.clear();
                val_ss << administration_subfield;
                *rd_administrator_subfield = val_ss.str();

                break;
            };
            default:
                LOG_WARN("%s: Unknown RD type: %d", peer_addr.c_str(), *rd_type);
                return false;
        }
        
        return true;
    }

    // TODO: Refactor this method as it's overloaded - each case statement can be its own method
    /**
     * Parse all EVPN nlri's
     *
     *
     * \details
     *      Parsing based on https://tools.ietf.org/html/rfc7432.  Will process all NLRI's in data.
     *
     * \param [in]   data                   Pointer to the start of the prefixes to be parsed
     * \param [in]   data_len               Length of the data in bytes to be read
     *
     */
    void EVPN::parseNlriData(u_char *data, uint16_t data_len) {
        u_char      *data_pointer = data;
        u_char      ip_binary[16];
        int         addr_bytes;
        char        ip_char[40];
        int         data_read = 0;

        while ((data_read + 10 /* min read */) <= data_len) {
            bgp::evpn_tuple tuple;

            //Cleanup variables in case of not modified
            tuple.mpls_label_1 = 0;
            tuple.mpls_label_2 = 0;
            tuple.mac_len = 0;
            tuple.ip_len = 0;


            // TODO: Keep an eye on this, as we might need to support add-paths for evpn
            tuple.path_id = 0;
            tuple.originating_router_ip_len = 0;

            size_t remaining = data_len - data_read;
            
            // Need at least 2 bytes for route type and length
            if (remaining < 2) {
                LOG_WARN("%s: Insufficient data for EVPN route type and length (need 2, have %zu)", 
                        peer_addr.c_str(), remaining);
                return;
            }

            uint8_t route_type = *data_pointer;
            data_pointer++;

            int len = *data_pointer;
            data_pointer++;

            data_read += 2;
            remaining -= 2;

            // Validate that we have enough data for the advertised length
            if (len > (int)remaining) {
                LOG_WARN("%s: EVPN route length %d exceeds remaining buffer %zu", 
                        peer_addr.c_str(), len, remaining);
                return;
            }

            // Need at least 8 bytes for RD
            if (len < 8 || remaining < 8) {
                LOG_WARN("%s: Insufficient data for Route Distinguisher in EVPN route (need 8, have len=%d, remaining=%zu)", 
                        peer_addr.c_str(), len, remaining);
                return;
            }

            if (!parseRouteDistinguisher(
                    data_pointer,
                    remaining,
                    &tuple.rd_type,
                    &tuple.rd_assigned_number,
                    &tuple.rd_administrator_subfield
            )) {
                LOG_WARN("%s: Failed to parse Route Distinguisher", peer_addr.c_str());
                return;
            }
            
            data_pointer += 8;
            data_read += 8;
            remaining -= 8;
            len -= 8; // len doesn't include the route type and len octets

            switch (route_type) {
                case EVPN_ROUTE_TYPE_ETHERNET_AUTO_DISCOVERY: {

                    // Ethernet Segment Identifier (10 bytes)
                    size_t esi_bytes_read = 0;
                    if (!parseEthernetSegmentIdentifier(data_pointer, remaining, 
                                                       &tuple.ethernet_segment_identifier, &esi_bytes_read)) {
                        LOG_WARN("%s: Failed to parse ESI for Ethernet Auto-Discovery route", peer_addr.c_str());
                        return;
                    }
                    
                    if (esi_bytes_read > remaining || esi_bytes_read > (size_t)len) {
                        LOG_WARN("%s: ESI bytes read %zu exceeds available data (remaining=%zu, len=%d)", 
                                peer_addr.c_str(), esi_bytes_read, remaining, len);
                        return;
                    }
                    
                    data_pointer += esi_bytes_read;
                    data_read += esi_bytes_read;
                    remaining -= esi_bytes_read;
                    len -= esi_bytes_read;

                    // Check if we have enough data for Ethernet Tag ID (4 bytes) + MPLS Label (3 bytes)
                    if (remaining < 7 || len < 7) {
                        LOG_WARN("%s: Insufficient data for Ethernet Tag ID and MPLS Label (need 7, have remaining=%zu, len=%d)", 
                                peer_addr.c_str(), remaining, len);
                        return;
                    }

                    //Ethernet Tag Id (4 bytes), printing in hex.
                    u_char ethernet_id[4];
                    bzero(&ethernet_id, 4);
                    memcpy(&ethernet_id, data_pointer, 4);
                    data_pointer += 4;

                    std::stringstream ethernet_tag_id_stream;

                    for (int i = 0; i < 4; i++) {
                        ethernet_tag_id_stream << std::hex << setfill('0') << setw(2) << (int) ethernet_id[i];
                    }

                    tuple.ethernet_tag_id_hex = ethernet_tag_id_stream.str();

                    //MPLS Label (3 bytes)
                    memcpy(&tuple.mpls_label_1, data_pointer, 3);
                    bgp::SWAP_BYTES(&tuple.mpls_label_1);
                    tuple.mpls_label_1 >>= 8;

                    data_pointer += 3;
                    data_read += 7;
                    remaining -= 7;
                    len -= 7;

                    break;
                }
                case EVPN_ROUTE_TYPE_MAC_IP_ADVERTISMENT: {

                    // Ethernet Segment Identifier (10 bytes)
                    size_t esi_bytes_read = 0;
                    if (!parseEthernetSegmentIdentifier(data_pointer, remaining, 
                                                       &tuple.ethernet_segment_identifier, &esi_bytes_read)) {
                        LOG_WARN("%s: Failed to parse ESI for MAC/IP Advertisement route", peer_addr.c_str());
                        return;
                    }
                    
                    if (esi_bytes_read > remaining || esi_bytes_read > (size_t)len) {
                        LOG_WARN("%s: ESI bytes read %zu exceeds available data (remaining=%zu, len=%d)", 
                                peer_addr.c_str(), esi_bytes_read, remaining, len);
                        return;
                    }
                    
                    data_pointer += esi_bytes_read;
                    data_read += esi_bytes_read;
                    remaining -= esi_bytes_read;
                    len -= esi_bytes_read;

                    // Check if we have enough data for Ethernet Tag ID (4 bytes) + MAC len (1 byte) + MAC (6 bytes) + IP len (1 byte)
                    if (remaining < 12 || len < 12) {
                        LOG_WARN("%s: Insufficient data for MAC/IP Advertisement (need at least 12, have remaining=%zu, len=%d)", 
                                peer_addr.c_str(), remaining, len);
                        return;
                    }

                    // Ethernet Tag ID (4 bytes)
                    u_char ethernet_id[4];
                    bzero(&ethernet_id, 4);
                    memcpy(&ethernet_id, data_pointer, 4);
                    data_pointer += 4;

                    std::stringstream ethernet_tag_id_stream;

                    for (int i = 0; i < 4; i++) {
                        ethernet_tag_id_stream << std::hex << setfill('0') << setw(2) << (int) ethernet_id[i];
                    }

                    tuple.ethernet_tag_id_hex = ethernet_tag_id_stream.str();

                    // MAC Address Length (1 byte)
                    uint8_t mac_address_length = *data_pointer;

                    tuple.mac_len = mac_address_length;
                    data_pointer++;

                    // MAC Address (6 byte)
                    tuple.mac.assign(bgp::parse_mac(data_pointer));
                    data_pointer += 6;

                    // IP Address Length (1 byte)
                    tuple.ip_len = *data_pointer;
                    data_pointer++;

                    data_read += 12;
                    remaining -= 12;
                    len -= 12;

                    addr_bytes = tuple.ip_len > 0 ? (tuple.ip_len / 8) : 0;
                    if (addr_bytes > (int)sizeof(ip_binary)) addr_bytes = sizeof(ip_binary);

                    if (tuple.ip_len > 0) {
                        if (addr_bytes > (int)remaining || addr_bytes > len) {
                            LOG_WARN("%s: IP address length %d exceeds available data (remaining=%zu, len=%d)", 
                                    peer_addr.c_str(), addr_bytes, remaining, len);
                            return;
                        }
                        
                        // IP Address (0, 4, or 16 bytes)
                        bzero(ip_binary, 16);
                        memcpy(&ip_binary, data_pointer, addr_bytes);

                        inet_ntop(tuple.ip_len > 32 ? AF_INET6 : AF_INET, ip_binary, ip_char, sizeof(ip_char));

                        tuple.ip = ip_char;

                        data_pointer += addr_bytes;
                        data_read += addr_bytes;
                        remaining -= addr_bytes;
                        len -= addr_bytes;
                    }

                    if (remaining < 3 || len < 3) {
                        LOG_WARN("%s: Insufficient data for MPLS Label (need 3, have remaining=%zu, len=%d)", 
                                peer_addr.c_str(), remaining, len);
                        return;
                    }

                    // MPLS Label1 (3 bytes)
                    memcpy(&tuple.mpls_label_1, data_pointer, 3);
                    bgp::SWAP_BYTES(&tuple.mpls_label_1);
                    tuple.mpls_label_1 >>= 8;

                    data_pointer += 3;
                    data_read += 3;
                    remaining -= 3;
                    len -= 3;

                    // Parse second label if present
                    if (len >= 3 && remaining >= 3) {
                        SELF_DEBUG("%s: parsing second evpn label\n", peer_addr.c_str());

                        memcpy(&tuple.mpls_label_2, data_pointer, 3);
                        bgp::SWAP_BYTES(&tuple.mpls_label_2);
                        tuple.mpls_label_2 >>= 8;

                        data_pointer += 3;
                        data_read += 3;
                        remaining -= 3;
                        len -= 3;
                    }

                    break;
                }
                case EVPN_ROUTE_TYPE_INCLUSIVE_MULTICAST_ETHERNET_TAG: {

                    if (remaining < 5 || len < 5) {
                        LOG_WARN("%s: Insufficient data for Inclusive Multicast Ethernet Tag (need 5, have remaining=%zu, len=%d)", 
                                peer_addr.c_str(), remaining, len);
                        return;
                    }

                    // Ethernet Tag ID (4 bytes)
                    u_char ethernet_id[4];
                    bzero(&ethernet_id, 4);
                    memcpy(&ethernet_id, data_pointer, 4);
                    data_pointer += 4;

                    std::stringstream ethernet_tag_id_stream;

                    for (int i = 0; i < 4; i++) {
                        ethernet_tag_id_stream << std::hex << setfill('0') << setw(2) << (int) ethernet_id[i];
                    }

                    tuple.ethernet_tag_id_hex = ethernet_tag_id_stream.str();

                    // IP Address Length (1 byte)
                    tuple.originating_router_ip_len = *data_pointer;
                    data_pointer++;

                    data_read += 5;
                    remaining -= 5;
                    len -= 5;

                    addr_bytes = tuple.originating_router_ip_len > 0 ? (tuple.originating_router_ip_len / 8) : 0;
                    if (addr_bytes > (int)sizeof(ip_binary)) addr_bytes = sizeof(ip_binary);

                    if (tuple.originating_router_ip_len > 0) {
                        if (addr_bytes > (int)remaining || addr_bytes > len) {
                            LOG_WARN("%s: Originating router IP length %d exceeds available data (remaining=%zu, len=%d)", 
                                    peer_addr.c_str(), addr_bytes, remaining, len);
                            return;
                        }

                        // Originating Router's IP Address (4 or 16 bytes)
                        bzero(ip_binary, 16);
                        memcpy(&ip_binary, data_pointer, addr_bytes);

                        inet_ntop(tuple.originating_router_ip_len > 32 ? AF_INET6 : AF_INET,
                                  ip_binary, ip_char, sizeof(ip_char));

                        tuple.originating_router_ip = ip_char;

                        data_pointer += addr_bytes;
                        data_read += addr_bytes;
                        remaining -= addr_bytes;
                        len -= addr_bytes;
                    }

                    break;
                }
                case EVPN_ROUTE_TYPE_ETHERNET_SEGMENT_ROUTE: {

                    // Ethernet Segment Identifier (10 bytes)
                    size_t esi_bytes_read = 0;
                    if (!parseEthernetSegmentIdentifier(data_pointer, remaining, 
                                                       &tuple.ethernet_segment_identifier, &esi_bytes_read)) {
                        LOG_WARN("%s: Failed to parse ESI for Ethernet Segment route", peer_addr.c_str());
                        return;
                    }
                    
                    if (esi_bytes_read > remaining || esi_bytes_read > (size_t)len) {
                        LOG_WARN("%s: ESI bytes read %zu exceeds available data (remaining=%zu, len=%d)", 
                                peer_addr.c_str(), esi_bytes_read, remaining, len);
                        return;
                    }
                    
                    data_pointer += esi_bytes_read;
                    data_read += esi_bytes_read;
                    remaining -= esi_bytes_read;
                    len -= esi_bytes_read;

                    // Check if we have enough data for IP Address Length (1 byte)
                    if (remaining < 1 || len < 1) {
                        LOG_WARN("%s: Insufficient data for IP Address Length (need 1, have remaining=%zu, len=%d)", 
                                peer_addr.c_str(), remaining, len);
                        return;
                    }

                    // IP Address Length (1 bytes)
                    tuple.originating_router_ip_len = *data_pointer;
                    data_pointer++;

                    data_read += 1;
                    remaining -= 1;
                    len -= 1;

                    addr_bytes = tuple.originating_router_ip_len > 0 ? (tuple.originating_router_ip_len / 8) : 0;
                    if (addr_bytes > (int)sizeof(ip_binary)) addr_bytes = sizeof(ip_binary);

                    if (tuple.originating_router_ip_len > 0) {
                        if (addr_bytes > (int)remaining || addr_bytes > len) {
                            LOG_WARN("%s: Originating router IP length %d exceeds available data (remaining=%zu, len=%d)", 
                                    peer_addr.c_str(), addr_bytes, remaining, len);
                            return;
                        }

                        // Originating Router's IP Address (4 or 16 bytes)
                        bzero(ip_binary, 16);
                        memcpy(&ip_binary, data_pointer, addr_bytes);

                        inet_ntop(tuple.originating_router_ip_len > 32 ? AF_INET6 : AF_INET,
                                  ip_binary, ip_char, sizeof(ip_char));

                        tuple.originating_router_ip = ip_char;

                        data_pointer += addr_bytes;
                        data_read += addr_bytes;
                        remaining -= addr_bytes;
                        len -= addr_bytes;
                    }

                    break;
                }
                default: {
                    LOG_INFO("%s: EVPN ROUTE TYPE %d is not implemented yet, skipping",
                             peer_addr.c_str(), route_type);
                    
                    // Skip the remaining length for this unknown route type
                    if (len > 0) {
                        if (len > (int)remaining) {
                            LOG_WARN("%s: Cannot skip unknown route type, len %d exceeds remaining %zu", 
                                    peer_addr.c_str(), len, remaining);
                            return;
                        }
                        data_pointer += len;
                        data_read += len;
                        remaining -= len;
                        len = 0;
                    }
                    break;
                }
            }

            if (isUnreach)
                parsed_data->evpn_withdrawn.push_back(tuple);
            else
                parsed_data->evpn.push_back(tuple);

            SELF_DEBUG("%s: Processed evpn NLRI read %d of %d, nlri len %d", peer_addr.c_str(),
                       data_read, data_len, len);
        }
    }
} /* namespace bgp_msg */