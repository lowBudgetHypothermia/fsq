/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 only,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License version 2 for more details (a copy is included
 * in the LICENSE file that accompanied this code).
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

/*
 * Copyright (c) 2019-2022, GSI Helmholtz Centre for Heavy Ion Research
 */

#include "common.h"

static int parse_line(char *line, struct kv_opt *kv_opt)
{
	if (line[0] == '#' || line[0] == '\n')
		return 0;

	const char *delim = " \t\r\n";
	char *token;
	char *saveptr;
	uint16_t cnt = 0;
	struct kv _kv = {.key = {0},
			 .val = {0}};

	token = strtok_r(line, delim, &saveptr);
	while(token != NULL) {
		if (token[0] == '#')
			break;
		strncpy(_kv.key, token, MAX_OPTIONS_LENGTH);
		cnt++;
		token = strtok_r(NULL, delim, &saveptr);
		if (token) {
			strncpy(_kv.val, token, MAX_OPTIONS_LENGTH);
			cnt++;
		}
		token = strtok_r(NULL, delim, &saveptr);
	}
	if (cnt != 2)
		return -EINVAL;

	kv_opt->kv = realloc(kv_opt->kv, sizeof(struct kv) * (kv_opt->N + 1));
	if (!kv_opt->kv)
		return -ENOMEM;

	memset(kv_opt->kv[kv_opt->N].key, 0, MAX_OPTIONS_LENGTH + 1);
	memset(kv_opt->kv[kv_opt->N].val, 0, MAX_OPTIONS_LENGTH + 1);
	strncpy(kv_opt->kv[kv_opt->N].key, _kv.key, MAX_OPTIONS_LENGTH + 1);
	strncpy(kv_opt->kv[kv_opt->N].val, _kv.val, MAX_OPTIONS_LENGTH + 1);
	kv_opt->N++;

	return 0;
}

ssize_t read_size(int fd, void *ptr, size_t n)
{
	size_t bytes_total = 0;
	char *buf;

	buf = ptr;
	while (bytes_total < n) {
		ssize_t bytes_read;

		bytes_read = read(fd, buf, n - bytes_total);

		if (bytes_read == 0)
			return bytes_total;
		if (bytes_read == -1)
			return -errno;

		bytes_total += bytes_read;
		buf += bytes_read;
	}

	return bytes_total;
}

ssize_t write_size(int fd, const void *ptr, size_t n)
{
	size_t bytes_total = 0;
	const char *buf;

	buf = ptr;
	while (bytes_total < n) {
		ssize_t bytes_written;

		bytes_written = write(fd, buf, n - bytes_total);

		if (bytes_written == 0)
			return bytes_total;
		if (bytes_written == -1)
			return -errno;

		bytes_total += bytes_written;
		buf += bytes_written;
	}

	return bytes_total;
}

int parse_conf(const char *filename, struct kv_opt *kv_opt)
{
	FILE *file = NULL;
	char *line = NULL;
	size_t len = 0;
	ssize_t nread;
	int rc = 0;

	file = fopen(filename, "r");
	if (!file) {
		LOG_ERROR(errno, "fopen failed on '%s'", filename);
		return -errno;
	}

	errno = 0;
	while ((nread = getline(&line, &len, file)) != -1) {
		rc = parse_line(line, kv_opt);
		if (rc == -EINVAL)
			LOG_WARN("malformed option '%s' in conf file '%s'",
				line, filename);
		else if (rc == -ENOMEM) {
			LOG_ERROR(rc, "realloc");
			goto cleanup;
		}
	}

	if (errno) {
		rc = -errno;
		LOG_ERROR(errno, "getline failed");
	}

cleanup:
	if (line) {
		free(line);
		line = NULL;
	}
	fclose(file);

	return rc;
}
