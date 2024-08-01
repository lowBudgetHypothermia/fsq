/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 only,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License version 2 for more details (a copy is included
 * in the LICENSE file that accompanied this code).
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

/*
 * Copyright (c) 2019-2024, GSI Helmholtz Centre for Heavy Ion Research
 */

#include <string.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <byteswap.h>
#include "fsqapi.h"
#include "log.h"

void fsq_packet_endian_swap(struct fsq_packet_t *fsq_packet)
{
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
	return;
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
	const enum fsq_protocol_state_t state = fsq_packet->state;
	fsq_packet->fsq_error.rc = bswap_32(fsq_packet->fsq_error.rc);
	fsq_packet->state = bswap_32(fsq_packet->state);

	if (state & FSQ_CONNECT)
		fsq_packet->fsq_login.port = bswap_32(fsq_packet->fsq_login.port);
	else if (state & FSQ_OPEN)
		fsq_packet->fsq_info.fsq_storage_dest =
			bswap_32(fsq_packet->fsq_info.fsq_storage_dest);
	else if (state & (FSQ_DATA))
		fsq_packet->fsq_data.size = bswap_64(fsq_packet->fsq_data.size);
#else
#error unsupported endianness
#endif
}

int fsq_send(struct fsq_session_t *fsq_session,
	     enum fsq_protocol_state_t fsq_protocol_state)
{
	int rc = 0;
	ssize_t bytes_send;

	if (!fsq_session || fsq_session->fd < 0)
		return -EINVAL;

	fsq_session->fsq_packet.ver = FSQ_PROTOCOL_VER;
	fsq_session->fsq_packet.state = fsq_protocol_state;

	fsq_packet_endian_swap(&(fsq_session->fsq_packet));

	bytes_send = write_size(fsq_session->fd, &fsq_session->fsq_packet,
				sizeof(struct fsq_packet_t));

	fsq_packet_endian_swap(&(fsq_session->fsq_packet));
	LOG_DEBUG("[fd=%d] fsq_send (%zd, %zd), "
		 "ver: %s, "
		 "state: '%s' = 0x%.4X, "
		 "error: %d, errstr: '%s'",
		 fsq_session->fd,
		 bytes_send, sizeof(struct fsq_packet_t),
		 FSQ_PROTOCOL_VER_STR(fsq_session->fsq_packet.ver),
		 FSQ_PROTOCOL_STR(fsq_session->fsq_packet.state),
		 fsq_session->fsq_packet.state,
		 fsq_session->fsq_packet.fsq_error.rc,
		 fsq_session->fsq_packet.fsq_error.strerror);
	if (bytes_send < 0) {
		rc = -errno;
		LOG_ERROR(rc, "bytes_send < 0");
		goto out;
	}
	if ((size_t)bytes_send != sizeof(struct fsq_packet_t)) {
		rc = -EPROTO;
		LOG_ERROR(rc, "bytes_send != sizeof(struct fsq_packet_t)");
	}

out:
	return rc;
}

int fsq_recv(struct fsq_session_t *fsq_session,
	     enum fsq_protocol_state_t fsq_protocol_state)
{
	int rc = 0;
	ssize_t bytes_recv;

	if (!fsq_session || fsq_session->fd < 0)
		return -EINVAL;

	bytes_recv = read_size(fsq_session->fd,
			       &fsq_session->fsq_packet,
			       sizeof(struct fsq_packet_t));

	fsq_packet_endian_swap(&(fsq_session->fsq_packet));

	LOG_DEBUG("[fd=%d] fsq_recv (%zd, %zd), "
		 "ver: (%s, %s), "
		 "state: ('%s' = 0x%.4X, '%s' = 0x%.4X), "
		 "error: %d, errstr: '%s'",
		 fsq_session->fd, bytes_recv,
		 sizeof(struct fsq_packet_t),
		 FSQ_PROTOCOL_VER_STR(fsq_session->fsq_packet.ver),
		 FSQ_PROTOCOL_VER_STR(FSQ_PROTOCOL_VER),
		 FSQ_PROTOCOL_STR(fsq_session->fsq_packet.state),
		 fsq_session->fsq_packet.state,
		 FSQ_PROTOCOL_STR(fsq_protocol_state),
		 fsq_protocol_state,
		 fsq_session->fsq_packet.fsq_error.rc,
		 fsq_session->fsq_packet.fsq_error.strerror);
	if (bytes_recv < 0) {
		rc = -errno;
		LOG_ERROR(rc, "bytes_recv < 0");
		return rc;
	}
	if (bytes_recv != sizeof(struct fsq_packet_t)) {
		rc = -EPROTO;
		LOG_ERROR(rc, "bytes_recv != sizeof(struct fsq_packet_t)");
		return rc;
	}

	/* Verify received fsq packet matches the expected state. */
	if (!(fsq_session->fsq_packet.state == (fsq_protocol_state) ||
	      fsq_session->fsq_packet.state & (fsq_protocol_state))) {
		rc = -EPROTO;
		LOG_ERROR(rc, "fsq protocol error");
	}

	return rc;
}

int fsq_init(struct fsq_login_t *fsq_login,
	      const char *node, const char *password, const char *hostname)
{
	if (!fsq_login || !node || !password || !hostname)
		return -EFAULT;

	if (strlen(node) > DSM_MAX_NODE_LENGTH
	    || strlen(password) > DSM_MAX_VERIFIER_LENGTH
	    || strlen(hostname) > HOST_NAME_MAX)
		return -EOVERFLOW;

	memset(fsq_login, 0, sizeof(*fsq_login));
	strncpy(fsq_login->node, node, DSM_MAX_NODE_LENGTH);
	strncpy(fsq_login->password, password, DSM_MAX_VERIFIER_LENGTH);
	strncpy(fsq_login->hostname, hostname, HOST_NAME_MAX);
	fsq_login->port = FSQ_PORT_DEFAULT;

	return 0;
}


int fsq_fconnect(struct fsq_login_t *fsq_login, struct fsq_session_t *fsq_session)
{
	int rc;
	struct addrinfo hints, *result, *rp;
	char port[6] = { 0 };
	char ipstr[INET6_ADDRSTRLEN] = { 0 };

	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_UNSPEC; /* Allow IPv4 or IPv6. */
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;
	hints.ai_protocol = 0;	/* Any protocol. */
	hints.ai_canonname = NULL;
	hints.ai_addr = NULL;
	hints.ai_next = NULL;

	snprintf(port, sizeof(port), "%d", fsq_login->port);
	rc = getaddrinfo(fsq_login->hostname, port, &hints, &result);
	if (rc) {
		LOG_ERROR(0, "getaddrinfo '%s:%s' failed: %s",
			  fsq_login->hostname, port,
			  gai_strerror(rc));
		rc = -errno;
		goto out;
	}

	/* The call getaddrinfo() returns a list of address structures.
	   Try each address until we successfully connect(). */
	for (rp = result; rp != NULL; rp = rp->ai_next) {

		void *addr;
		char *ipver;

		/* Obtain IP information on address and v4 or v6 for later usage. */
		if (rp->ai_family == AF_INET) {
			struct sockaddr_in *ipv4 = (struct sockaddr_in *)rp->ai_addr;
			addr = &(ipv4->sin_addr);
			ipver = "IPv4";
		} else {
			struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)rp->ai_addr;
			addr = &(ipv6->sin6_addr);
			ipver = "IPv6";
		}
		inet_ntop(rp->ai_family, addr, ipstr, sizeof(ipstr));

		fsq_session->fd = socket(rp->ai_family,
					 rp->ai_socktype, rp->ai_protocol);

		/* Try next address. */
		if (fsq_session->fd < 0) {
			rc = -errno;
			LOG_ERROR(rc, "socket %s:%s, try next address", ipver, ipstr);
			continue;
		}

		rc = connect(fsq_session->fd, rp->ai_addr, rp->ai_addrlen);
		if (!rc) {
			LOG_INFO("connecting to %s:%s '%s:%d'", ipver, ipstr,
				 fsq_login->hostname, fsq_login->port);
			break;	/* Success. */
		}

		rc = -errno;
		if (rp->ai_family == AF_INET6)
			LOG_INFO("connect using address %s:%s failed, %s, try next address",
				 ipver, ipstr, strerror(-rc));
		else
			LOG_ERROR(rc, "connect using address %s:%s failed, try next address",
				  ipver, ipstr);
		close(fsq_session->fd);
		fsq_session->fd = -1;
	}
	freeaddrinfo(result);

	/* No address succeeded. */
	if (rp == NULL || fsq_session->fd == -1) {
		if (!rc)
			rc = -EADDRNOTAVAIL;
		goto out;
	}

	memcpy(&fsq_session->fsq_packet.fsq_login,
	       fsq_login, sizeof(struct fsq_login_t));
	rc = fsq_send(fsq_session, FSQ_CONNECT);
	if (rc)
		goto out;

	rc = fsq_recv(fsq_session, FSQ_CONNECT | FSQ_REPLY);

out:
        if (rc)
                close(fsq_session->fd);

        return fsq_session->fsq_packet.fsq_error.rc != 0 ?
		fsq_session->fsq_packet.fsq_error.rc : rc;
}

void fsq_fdisconnect(struct fsq_session_t *fsq_session)
{
	fsq_send(fsq_session, FSQ_DISCONNECT);
	close(fsq_session->fd);
}

static int __fsq_fopen(const char *fs, const char *fpath, const char *desc,
		       enum fsq_storage_dest_t fsq_storage_dest,
		       struct fsq_session_t *fsq_session)
{
	int rc = 0;
	struct fsq_info_t fsq_info = {
		.fs		   = {0},
		.fpath		   = {0},
		.desc		   = {0},
		.fsq_storage_dest  = fsq_storage_dest
	};

	if (!fsq_session)
		return -EFAULT;

	if (!(fs && fpath)) {
		close(fsq_session->fd);
		return -EFAULT;
	}

	/* Fillup struct fsq_info_t with fs, fpath, desc. */
	strncpy(fsq_info.fs, fs, DSM_MAX_FSNAME_LENGTH);
	strncpy(fsq_info.fpath, fpath, PATH_MAX);
	if (desc)
		strncpy(fsq_info.desc, desc, DSM_MAX_DESCR_LENGTH);
	memcpy(&(fsq_session->fsq_packet.fsq_info),
	       &fsq_info, sizeof(fsq_info));

	rc = fsq_send(fsq_session, FSQ_OPEN);
	if (rc) {
		close(fsq_session->fd);
		return rc;
	}

	rc = fsq_recv(fsq_session, FSQ_OPEN | FSQ_REPLY);
        if (rc) {
                close(fsq_session->fd);
		return rc;
	}

        return fsq_session->fsq_packet.fsq_error.rc != 0 ?
		fsq_session->fsq_packet.fsq_error.rc : rc;
}

int fsq_fopen(const char *fs, const char *fpath, const char *desc,
	      struct fsq_session_t *fsq_session)
{
	return __fsq_fopen(fs, fpath, desc, FSQ_STORAGE_LUSTRE_TSM, fsq_session);
}

int fsq_fdopen(const char *fs, const char *fpath, const char *desc,
	       enum fsq_storage_dest_t fsq_storage_dest,
	       struct fsq_session_t *fsq_session)
{
	return __fsq_fopen(fs, fpath, desc, fsq_storage_dest, fsq_session);
}

ssize_t fsq_fwrite(const void *ptr, size_t size, size_t nmemb,
		   struct fsq_session_t *fsq_session)
{
	int rc;
	ssize_t bytes_written;

	fsq_session->fsq_packet.fsq_data.size = size * nmemb;
	/* Note inside fsq_send the endianess is changed to little endian
	   when on big endian architecture */
	rc = fsq_send(fsq_session, FSQ_DATA);
	if (rc) {
		close(fsq_session->fd);
		return rc;
	}
	/* If we are on big endian architecture we have to convert little
	   endian (changed above) back to big endian. */
	fsq_packet_endian_swap(&fsq_session->fsq_packet);

	bytes_written = write_size(fsq_session->fd, ptr,
				   fsq_session->fsq_packet.fsq_data.size);
	LOG_DEBUG("[fd=%d] write size %zd, expected size %zd",
		 fsq_session->fd, bytes_written,
		 __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__ ?
		 fsq_session->fsq_packet.fsq_data.size :
		 bswap_64(fsq_session->fsq_packet.fsq_data.size));

	rc = fsq_recv(fsq_session, (FSQ_DATA | FSQ_REPLY));
	if (rc) {
		close(fsq_session->fd);
		return rc;
	}

	if (fsq_session->fsq_packet.fsq_error.rc)
		return fsq_session->fsq_packet.fsq_error.rc;

	return bytes_written;
}

int fsq_fclose(struct fsq_session_t *fsq_session)
{
	int rc;

	rc = fsq_send(fsq_session, FSQ_CLOSE);
	if (rc) {
		close(fsq_session->fd);
		return rc;
	}

	rc = fsq_recv(fsq_session, (FSQ_CLOSE | FSQ_REPLY));
	if (rc) {
		close(fsq_session->fd);
		return rc;
	}

        return fsq_session->fsq_packet.fsq_error.rc != 0 ?
		fsq_session->fsq_packet.fsq_error.rc : rc;
}
