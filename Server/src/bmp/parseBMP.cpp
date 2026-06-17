/*
 * Copyright (c) 2013-2015 Cisco Systems, Inc. and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 *
 */

#include "parseBMP.h"
#include "MsgBusInterface.hpp"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <sys/time.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include "bgp_common.h"

/**
 * Constructor for class
 *
 * \note
 *  This class will allocate via 'new' the bgp_peers variables
 *        as needed.  The calling method/class/function should check each var
 *        in the structure for non-NULL pointers.  Non-NULL pointers need to be
 *        freed with 'delete'
 *
 * \param [in]     logPtr      Pointer to existing Logger for app logging
 * \param [in,out] peer_entry  Pointer to the peer entry
 */
parseBMP::parseBMP(Logger *logPtr, MsgBusInterface::obj_bgp_peer *peer_entry) {
    debug = false;
    bmp_type = -1; // Initially set to error
    bmp_len = 0;
    logger = logPtr;

    bmp_data_len = 0;
    bzero(bmp_data, sizeof(bmp_data));

    bmp_packet_len = 0;
    bzero(bmp_packet, sizeof(bmp_packet));

    // Set the passed storage for the router entry items.
    p_entry = peer_entry;
    bzero(p_entry, sizeof(MsgBusInterface::obj_bgp_peer));
}

parseBMP::~parseBMP() {
    // clean up
}

/**
 * Recv wrapper for recv() to enable packet buffering
 */
ssize_t parseBMP::Recv(int sockfd, void *buf, size_t len, int flags) {
    ssize_t read = recv(sockfd, buf, len, flags);

    if (read > 0)
        if ((bmp_packet_len + read) < BMP_PACKET_BUF_SIZE) {
            memcpy(&bmp_packet[bmp_packet_len], buf, read);
            bmp_packet_len += read;
        }

    return read;
}

/**
 * Process the incoming BMP message
 *
 * \returns
 *      returns the BMP message type. A type of >= 0 is normal,
 *      < 0 indicates an error
 *
 * \param [in] sock     Socket to read the BMP message from
 *
 * \throws (const char *) on error.   String will detail error message.
 */
char parseBMP::handleMessage(int sock) {
    unsigned char ver;
    ssize_t bytes_read;

    // Get the version in order to determine what we read next
    //    As of Junos 10.4R6.5, it supports version 1
    bytes_read = Recv(sock, &ver, 1, MSG_WAITALL);

    if (bytes_read < 0)
        throw "(1) Failed to read from socket.";
    else if (bytes_read == 0)
        throw "(2) Connection closed";
    else if (bytes_read != 1)
        throw "(3) Cannot read the BMP version byte from socket";

    // check the version
    if (ver == 3) { // draft-ietf-grow-bmp-04 - 07
        parseBMPv3(sock);
    }

    // Handle the older versions
    else if (ver == 1 || ver == 2) {
        SELF_DEBUG("Older BMP version of %d, consider upgrading the router to support BMPv3", ver);
        parseBMPv2(sock);

    } else
        throw "ERROR: Unsupported BMP message version";

    SELF_DEBUG("BMP version = %d\n", ver);

    return bmp_type;
}

/**
* Parse v1 and v2 BMP header
*
* \details
*      v2 uses the same common header, but adds the Peer Up message type.
*
* \param [in]  sock        Socket to read the message from
*/
void parseBMP::parseBMPv2(int sock) {
    struct common_hdr_old c_hdr = { 0 };
    ssize_t i = 0;
    char buf[256] = {0};

    SELF_DEBUG("parseBMP: sock=%d: Reading %d bytes", sock, BMP_HDRv1v2_LEN);

    bmp_len = 0;

    if ((i = Recv(sock, &c_hdr, BMP_HDRv1v2_LEN, MSG_WAITALL))
            != BMP_HDRv1v2_LEN) {
        SELF_DEBUG("sock=%d: Couldn't read all bytes, read %zd bytes",
                sock, i);
        throw "ERROR: Cannot read v1/v2 BMP common header.";
    }
    // Process the message based on type
    bmp_type = c_hdr.type;
    switch (c_hdr.type) {
        case 0: // Route monitoring
            SELF_DEBUG("sock=%d : BMP MSG : route monitor", sock);

            // Get the length of the remaining message by reading the BGP length
            if ((i=Recv(sock, buf, 18, MSG_PEEK | MSG_WAITALL)) == 18) {
                uint16_t len;
                memcpy(&len, (buf+16), 2);
                bgp::SWAP_BYTES(&len);
                bmp_len = len;

            } else {
                LOG_ERR("sock=%d: Failed to read BGP message to get length of BMP message", sock);
                throw "Failed to read BGP message for BMP length";
            }
            break;

        case 1: // Statistics Report
            SELF_DEBUG("sock=%d : BMP MSG : stats report", sock);
            LOG_INFO("sock=%d : BMP MSG : stats report", sock);
            break;

        case 2: // Peer down notification
            LOG_INFO("sock=%d: BMP MSG: Peer down", sock);

            // Get the length of the remaining message by reading the BGP length
            if ((i=Recv(sock, buf, 1, MSG_PEEK)) != 1) {

                // Is there a BGP message
                if (buf[0] == 1 or buf[0] == 3) {
                    if ((i = Recv(sock, buf, 18, MSG_PEEK | MSG_WAITALL)) == 18) {
                        memcpy(&bmp_len, buf + 16, 2);
                        bgp::SWAP_BYTES(&bmp_len);

                    } else {
                        LOG_ERR("sock=%d: Failed to read peer down BGP message to get length of BMP message", sock);
                        throw "Failed to read BGP message for BMP length";
                    }
                }
            } else {
                LOG_ERR("sock=%d: Failed to read peer down reason", sock);
                throw "Failed to read BMP peer down reason";
            }

            SELF_DEBUG("sock=%d : BMP MSG : peer down", sock);
            break;

        case 3: // Peer Up notification
            LOG_ERR("sock=%d: Peer UP not supported with older BMP version since no one has implemented it", sock);

            SELF_DEBUG("sock=%d : BMP MSG : peer up", sock);
            throw "ERROR: Will need to add support for peer up if it's really used.";
            break;
    }

    SELF_DEBUG("sock=%d : Peer Type is %d", sock, c_hdr.peer_type);

    if (c_hdr.peer_flags & 0x80) { // V flag of 1 means this is IPv6
        p_entry->isIPv4 = false;
        inet_ntop(AF_INET6, c_hdr.peer_addr, peer_addr, sizeof(peer_addr));

        SELF_DEBUG("sock=%d : Peer address is IPv6", sock);

    } else {
        p_entry->isIPv4 = true;
        snprintf(peer_addr, sizeof(peer_addr), "%d.%d.%d.%d",
                c_hdr.peer_addr[12], c_hdr.peer_addr[13], c_hdr.peer_addr[14],
                c_hdr.peer_addr[15]);

        SELF_DEBUG("sock=%d : Peer address is IPv4", sock);
    }

    if (c_hdr.peer_flags & 0x40) { // L flag of 1 means this is Loc-RIP and not Adj-RIB-In
        SELF_DEBUG("sock=%d : Msg is for Loc-RIB", sock);
    } else {
        SELF_DEBUG("sock=%d : Msg is for Adj-RIB-In", sock);
    }

    // convert the BMP byte messages to human readable strings
    snprintf(peer_as, sizeof(peer_as), "0x%04x%04x",
            c_hdr.peer_as[0] << 8 | c_hdr.peer_as[1],
            c_hdr.peer_as[2] << 8 | c_hdr.peer_as[3]);
    snprintf(peer_bgp_id, sizeof(peer_bgp_id), "%d.%d.%d.%d",
            c_hdr.peer_bgp_id[0], c_hdr.peer_bgp_id[1], c_hdr.peer_bgp_id[2],
            c_hdr.peer_bgp_id[3]);

    // Format based on the type of RD
    switch (c_hdr.peer_dist_id[0] << 8 | c_hdr.peer_dist_id[1]) {
        case 1: // admin = 4bytes (IP address), assign number = 2bytes
            snprintf(peer_rd, sizeof(peer_rd), "%d.%d.%d.%d:%d",
                    c_hdr.peer_dist_id[2], c_hdr.peer_dist_id[3],
                    c_hdr.peer_dist_id[4], c_hdr.peer_dist_id[5],
                    c_hdr.peer_dist_id[6] << 8 | c_hdr.peer_dist_id[7]);
            break;
        case 2: // admin = 4bytes (ASN), assing number = 2bytes
            snprintf(peer_rd, sizeof(peer_rd), "%lu:%d",
                    (unsigned long) (c_hdr.peer_dist_id[2] << 24
                            | c_hdr.peer_dist_id[3] << 16
                            | c_hdr.peer_dist_id[4] << 8 | c_hdr.peer_dist_id[5]),
                    c_hdr.peer_dist_id[6] << 8 | c_hdr.peer_dist_id[7]);
            break;
        default: // admin = 2 bytes, sub field = 4 bytes
            snprintf(peer_rd, sizeof(peer_rd), "%d:%lu",
                    c_hdr.peer_dist_id[1] << 8 | c_hdr.peer_dist_id[2],
                    (unsigned long) (c_hdr.peer_dist_id[3] << 24
                            | c_hdr.peer_dist_id[4] << 16
                            | c_hdr.peer_dist_id[5] << 8 | c_hdr.peer_dist_id[6]
                            | c_hdr.peer_dist_id[7]));
            break;
    }

    // Update the MySQL peer entry struct
    strncpy(p_entry->peer_addr, peer_addr, sizeof(peer_addr));
    p_entry->peer_as = strtoll(peer_as, NULL, 16);
    strncpy(p_entry->peer_bgp_id, peer_bgp_id, sizeof(peer_bgp_id));
    strncpy(p_entry->peer_rd, peer_rd, sizeof(peer_rd));

    // Save the advertised timestamp
    uint32_t ts = c_hdr.ts_secs;
    bgp::SWAP_BYTES(&ts);
    if (ts != 0)
        p_entry->timestamp_secs = ts;
    else
        p_entry->timestamp_secs = time(NULL);

    // Is peer type L3VPN peer or global instance
    if (c_hdr.type == 1) // L3VPN
        p_entry->isL3VPN = 1;
    else
        // Global Instance
        p_entry->isL3VPN = 0;

    SELF_DEBUG("sock=%d : Peer Address = %s", sock, peer_addr);
    SELF_DEBUG("sock=%d : Peer AS = (%x-%x)%x:%x", sock,
            c_hdr.peer_as[0], c_hdr.peer_as[1], c_hdr.peer_as[2],
            c_hdr.peer_as[3]);
    SELF_DEBUG("sock=%d : Peer RD = %s", sock, peer_rd);
}

/**
 * Parse v3 BMP header
 *
 * \details
 *      v3 has a different header structure and changes the peer
 *      header format.
 *
 * \param [in]  sock        Socket to read the message from
 */
void parseBMP::parseBMPv3(int sock) {
    struct common_hdr_v3 c_hdr = { 0 };

    SELF_DEBUG("Parsing BMP version 3 (rfc7854)");
    if ((Recv(sock, &c_hdr, BMP_HDRv3_LEN, MSG_WAITALL)) != BMP_HDRv3_LEN) {
        throw "ERROR: Cannot read v3 BMP common header.";
    }

    // Change to host order
    bgp::SWAP_BYTES(&c_hdr.len);

    SELF_DEBUG("BMP v3: type = %x len=%d", c_hdr.type, c_hdr.len);

    // Adjust length to remove common header size
    c_hdr.len -= 1 + BMP_HDRv3_LEN;

    if (c_hdr.len > BGP_MAX_MSG_SIZE)
        throw "ERROR: BMP length is larger than max possible BGP size";

    // Parse additional headers based on type
    bmp_type = c_hdr.type;
    bmp_len = c_hdr.len;

    switch (c_hdr.type) {
        case TYPE_ROUTE_MON: // Route monitoring
            SELF_DEBUG("BMP MSG : route monitor");
            parsePeerHdr(sock);
            break;

        case TYPE_STATS_REPORT: // Statistics Report
            SELF_DEBUG("BMP MSG : stats report");
            parsePeerHdr(sock);
            break;

        case TYPE_PEER_UP: // Peer Up notification
        {
            SELF_DEBUG("BMP MSG : peer up");
            parsePeerHdr(sock);

            break;
        }
        case TYPE_PEER_DOWN: // Peer down notification
            SELF_DEBUG("BMP MSG : peer down");
            parsePeerHdr(sock);
            break;

        case TYPE_INIT_MSG:
        case TYPE_TERM_MSG:
            // Allowed
            break;

        default:
            LOG_ERR("ERROR: Unknown BMP message type of %d", c_hdr.type);
            throw "ERROR: BMP message type is not supported";
            break;
    }
}

/**
 * Parse BMP peer header flags by peer type
 *
 *  This method will update the instance variable "p_entry"
 *
 * \param [in] peer_type         peer type from peer header
 * \param [in] peer_flags        flags from peer header
 *
 */
void parseBMP::parsePeerFlags(u_char peer_type, u_char peer_flags) {

    switch (peer_type) {
        case 3: // Local RIB (draft-ietf-grow-bmp-local-rib)
            p_entry->isLocRib = true;

            if (peer_flags & 0x80) {  // Indicates if the local-rib is filtered
                p_entry->isLocRibFiltered = true;
            }

            break;

        default:
            p_entry->isLocRib = false;

            if (peer_flags & 0x80) { // V flag of 1 means this is IPv6
                p_entry->isIPv4 = false;

            } else {
                p_entry->isIPv4 = true;
            }

            if (peer_flags & 0x10) { // O flag of 1 means this is Adj-Rib-Out
                SELF_DEBUG("Msg is for Adj-RIB-Out");
                p_entry->isAdjIn = false;
            }

            if (peer_flags & 0x20) { // A flag of 1 means 2-octet encoding
                SELF_DEBUG("Msg is 2-octet encoded");
                p_entry->isTwoOctet = true;
            }

            if (peer_flags & 0x40) { // L flag of 1 means this is post-policy of Adj-RIB-In
                SELF_DEBUG("Msg is for POST-POLICY Adj-RIB-In");
                p_entry->isPrePolicy = false;
            } else {
                SELF_DEBUG("Msg is for PRE-POLICY Adj-RIB-In");
                p_entry->isPrePolicy = true;
                p_entry->isAdjIn = true;
            }

            // Is peer type L3VPN peer or global instance
            if (peer_type == 1) // L3VPN
                p_entry->isL3VPN = 1;

            else
                // Global Instance
                p_entry->isL3VPN = 0;

            break;
    }

}

/**
 * Parse the v3 peer header
 *
 * \param [in]  sock        Socket to read the message from
 */
void parseBMP::parsePeerHdr(int sock) {
    peer_hdr_v3 p_hdr = {0};
    int i;

    bzero(&p_hdr, sizeof(p_hdr));

    if ((i = Recv(sock, &p_hdr, BMP_PEER_HDR_LEN, MSG_WAITALL))
        != BMP_PEER_HDR_LEN) {
        LOG_ERR("sock=%d: Couldn't read all bytes, read %d bytes",
                sock, i);
    }

    // Adjust the common header length to remove the peer header (as it's been read)
    bmp_len -= BMP_PEER_HDR_LEN;

    SELF_DEBUG("parsePeerHdr: sock=%d : Peer Type is %d", sock,
               p_hdr.peer_type);

    parsePeerFlags(p_hdr.peer_type, p_hdr.peer_flags);

    if (p_entry->isIPv4) {
        snprintf(peer_addr, sizeof(peer_addr), "%d.%d.%d.%d",
                 p_hdr.peer_addr[12], p_hdr.peer_addr[13], p_hdr.peer_addr[14],
                 p_hdr.peer_addr[15]);
        SELF_DEBUG("sock=%d : Peer address is IPv4 %s", sock,
                   peer_addr);

    }
    else {
        inet_ntop(AF_INET6, p_hdr.peer_addr, peer_addr, sizeof(peer_addr));

        SELF_DEBUG("sock=%d : Peer address is IPv6 %s", sock,
                   peer_addr);
    }


    // convert the BMP byte messages to human readable strings
    snprintf(peer_as, sizeof(peer_as), "0x%04x%04x",
             p_hdr.peer_as[0] << 8 | p_hdr.peer_as[1],
             p_hdr.peer_as[2] << 8 | p_hdr.peer_as[3]);

    inet_ntop(AF_INET, p_hdr.peer_bgp_id, peer_bgp_id, sizeof(peer_bgp_id));
    SELF_DEBUG("sock=%d : Peer BGP-ID %x.%x.%x.%x (%s)", sock, p_hdr.peer_bgp_id[0],
               p_hdr.peer_bgp_id[1],p_hdr.peer_bgp_id[2],p_hdr.peer_bgp_id[3], peer_bgp_id);

    // Format based on the type of RD
    SELF_DEBUG("sock=%d : Peer RD type = %d %d", sock, p_hdr.peer_dist_id[0], p_hdr.peer_dist_id[1]);
    switch (p_hdr.peer_dist_id[1]) {
        case 1: // admin = 4bytes (IP address), assign number = 2bytes
            snprintf(peer_rd, sizeof(peer_rd), "%d.%d.%d.%d:%d",
                     p_hdr.peer_dist_id[2], p_hdr.peer_dist_id[3],
                     p_hdr.peer_dist_id[4], p_hdr.peer_dist_id[5],
                     p_hdr.peer_dist_id[6] << 8 | p_hdr.peer_dist_id[7]);
            break;

        case 2: // admin = 4bytes (ASN), sub field 2bytes
            snprintf(peer_rd, sizeof(peer_rd), "%lu:%d",
                     (unsigned long) (p_hdr.peer_dist_id[2] << 24
                                      | p_hdr.peer_dist_id[3] << 16
                                      | p_hdr.peer_dist_id[4] << 8 | p_hdr.peer_dist_id[5]),
                     p_hdr.peer_dist_id[6] << 8 | p_hdr.peer_dist_id[7]);
            break;
        default: // Type 0:  // admin = 2 bytes, sub field = 4 bytes
            snprintf(peer_rd, sizeof(peer_rd), "%d:%lu",
                     p_hdr.peer_dist_id[2] << 8 | p_hdr.peer_dist_id[3],
                     (unsigned long) (p_hdr.peer_dist_id[4] << 24
                                      | p_hdr.peer_dist_id[5] << 16
                                      | p_hdr.peer_dist_id[6] << 8 | p_hdr.peer_dist_id[7]));
            break;
    }

    // Update the DB peer entry struct
    strncpy(p_entry->peer_addr, peer_addr, sizeof(p_entry->peer_addr));
    p_entry->peer_as = strtoll(peer_as, NULL, 16);
    strncpy(p_entry->peer_bgp_id, peer_bgp_id, sizeof(p_entry->peer_bgp_id));
    strncpy(p_entry->peer_rd, peer_rd, sizeof(p_entry->peer_rd));

    // Save the advertised timestamp
    bgp::SWAP_BYTES(&p_hdr.ts_secs);
    bgp::SWAP_BYTES(&p_hdr.ts_usecs);

    if (p_hdr.ts_secs != 0) {
        p_entry->timestamp_secs = p_hdr.ts_secs;

        if (p_hdr.ts_usecs < 1000000)
            p_entry->timestamp_us = p_hdr.ts_usecs;
        else
            p_entry->timestamp_us = p_hdr.ts_usecs % 1000000;

    } else {
        timeval tv;

        gettimeofday(&tv, NULL);
        p_entry->timestamp_secs = tv.tv_sec;
        p_entry->timestamp_us = tv.tv_usec;
    }


    SELF_DEBUG("sock=%d : Peer Address = %s", sock, peer_addr);
    SELF_DEBUG("sock=%d : Peer AS = (%x-%x)%x:%x", sock,
                p_hdr.peer_as[0], p_hdr.peer_as[1], p_hdr.peer_as[2],
                p_hdr.peer_as[3]);
    SELF_DEBUG("sock=%d : Peer RD = %s", sock, peer_rd);
}

/**
 * Parse the v3 peer down BMP header
 *
 * \details This method will update the db peer_down_event struct with BMP header info.
 *
 * \param [in]  sock       Socket to read the message from
 * \param [out] down_event Reference to the peer down event storage (will be updated with bmp info)
 *
 * \returns true if successfully parsed the bmp peer down header, false otherwise
 */
bool parseBMP::parsePeerDownEventHdr(int sock, MsgBusInterface::obj_peer_down_event &down_event) {
    char reason;

    if (Recv(sock, &reason, 1, 0) == 1) {
        LOG_NOTICE("sock=%d : %s: BGP peer down notification with reason code: %d",
                    sock, p_entry->peer_addr, reason);

        // Indicate that data has been read
        bmp_len--;

        // Initialize the down_event struct
        down_event.bmp_reason = reason;

    } else {
        return false;
    }

    return true;
}

/**
 * Buffer remaining BMP message
 *
 * \details This method will read the remaining amount of BMP data and store it in the instance variable bmp_data.
 *          Normally this is used to store the BGP message so that it can be parsed.
 *
 * \param [in]  sock       Socket to read the message from
 *
 * \returns true if successfully parsed the bmp peer down header, false otherwise
 *
 * \throws String error
 */
void parseBMP::bufferBMPMessage(int sock) {
    if (bmp_len <= 0)
        return;

    if (bmp_len > sizeof(bmp_data)) {
        LOG_WARN("sock=%d: BMP message is invalid, length of %d is larger than max buffer size of %d",
                sock, bmp_len, sizeof(bmp_data));
        throw "BMP message length is too large for buffer, invalid BMP sender";
    }

    SELF_DEBUG("sock=%d: Buffering %d from socket", sock, bmp_len);
    if ((bmp_data_len=Recv(sock, bmp_data, bmp_len, MSG_WAITALL)) != bmp_len) {
         LOG_ERR("sock=%d: Couldn't read all %d bytes into buffer",
                 sock, bmp_len);
         throw "Error while reading BMP data into buffer";
    }

    // Indicate no more data is left to read
    bmp_len = 0;

}

/**
 * Parse the peer UP informational data
 *
 * \details Updates the peer struct info items
 *
 * \param [in] data         Data pointer to info, should start at start of info TLV
 * \param [in] len          Length of info TLV data to read
 */
void parseBMP::parsePeerUpInfo(u_char *data, int len) {
    info_tlv_msg info;
    char infoBuf[255];
    int infoLen;
    u_char *bufPtr = data;

    /*
     * Loop through the info TLV's (in buffer) and parse each TLV
     */
    for (int i = 0; i < len; i += BMP_INFO_TLV_HDR_LEN) {

        memcpy(&info, bufPtr, BMP_INFO_TLV_HDR_LEN);
        info.info = NULL;
        bgp::SWAP_BYTES(&info.len);
        bgp::SWAP_BYTES(&info.type);

        bufPtr += BMP_INFO_TLV_HDR_LEN;                // Move pointer past the info header

        SELF_DEBUG("Peer info message type %hu and length %hu parsed", info.type, info.len);

        if (info.len > 0) {
            infoLen = sizeof(infoBuf) < info.len ? sizeof(infoBuf) : info.len;
            bzero(infoBuf, sizeof(infoBuf));
            memcpy(infoBuf, bufPtr, infoLen);
            bufPtr += infoLen;                     // Move pointer past the info data
            i += infoLen;                          // Update the counter past the info data

            info.info = infoBuf;

        }

        /*
         * Save the data based on info type
         */
        switch (info.type) {
            case INFO_TLV_PEER_VRF_TABLE :
                infoLen = sizeof(p_entry->table_name) < (info.len - 1) ? (sizeof(p_entry->table_name) - 1)
                                                                       : info.len;
                memcpy(p_entry->table_name, info.info, infoLen);
                LOG_INFO("Peer table/vrf name %hu = %s", info.type, p_entry->table_name);

                break;

            default:
                LOG_NOTICE("Peer info message type %hu is not implemented", info.type);
        }
    }
}

/**
 * Parse the v3 peer up BMP header
 *
 * \details This method will update the db peer_up_event struct with BMP header info.
 *
 * \param [in]  sock     Socket to read the message from
 * \param [out] up_event Reference to the peer up event storage (will be updated with bmp info)
 *
 * \returns true if successfully parsed the bmp peer up header, false otherwise
 */
bool parseBMP::parsePeerUpEventHdr(int sock, MsgBusInterface::obj_peer_up_event &up_event) {


    unsigned char local_addr[16];
    bool isParseGood = true;
    int bytes_read = 0;

    // Get the local address
    if ( Recv(sock, &local_addr, 16, MSG_WAITALL) != 16)
        isParseGood = false;
    else
        bytes_read += 16;

    if (isParseGood and p_entry->isIPv4) {
        snprintf(up_event.local_ip, sizeof(up_event.local_ip), "%d.%d.%d.%