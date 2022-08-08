#include "util.h"

int crc32file(const char *filename, uint32_t *crc32result)
{
	int rc = 0;
	FILE *file;
	size_t cur_read;
	uint32_t crc32sum = 0;
	unsigned char buf[TSM_BUF_LENGTH] = {0};

	file = fopen(filename, "r");
	if (file == NULL) {
		rc = -errno;
		CT_ERROR(rc, "fopen failed on '%s'", filename);

		return rc;
	}

	do {
		cur_read = fread(buf, 1, TSM_BUF_LENGTH, file);
		if (ferror(file)) {
			rc = -EIO;
			CT_ERROR(rc, "fread failed on '%s'", filename);
			break;
		}
		crc32sum = crc32(crc32sum, (const unsigned char *)buf,
				 cur_read);

	} while (!feof(file));

	int rc_minor;

	rc_minor = fclose(file);
	if (rc_minor) {
		rc_minor = -errno;
		CT_ERROR(rc_minor, "fclose failed on '%s'", filename);

		return rc_minor;
	}

	*crc32result = crc32sum;

	return rc;
}

void login_init(struct login_t *login, const char *servername,
                const char *node, const char *password,
                const char *owner, const char *platform,
                const char *fsname, const char *fstype)
{
        if (!login || !servername)
                return;

        const uint16_t s_arg_len = 1 + strlen(servername) +
                strlen("-se=");
        if (s_arg_len < MAX_OPTIONS_LENGTH)
                snprintf(login->options, s_arg_len, "-se=%s", servername);
        else
                CT_WARN("Option parameter \'-se=%s\' is larger than "
                        "MAX_OPTIONS_LENGTH: %d and is ignored\n",
                        servername, MAX_OPTIONS_LENGTH);

        if (node)
                strncpy(login->node, node, DSM_MAX_NODE_LENGTH);
        else
                login->node[0] = '\0';
        if (password)
                strncpy(login->password, password, DSM_MAX_VERIFIER_LENGTH);
        else
                login->password[0] = '\0';
        if (owner)
                strncpy(login->owner, owner, DSM_MAX_OWNER_LENGTH);
        else
                login->owner[0] = '\0';
        if (platform)
                strncpy(login->platform, platform, DSM_MAX_PLATFORM_LENGTH);
        else
                login->platform[0] = '\0';
        if (fsname)
                strncpy(login->fsname, fsname, DSM_MAX_FSNAME_LENGTH);
        else
                login->fsname[0] = '\0';
        if (fstype)
                strncpy(login->fstype, fstype, DSM_MAX_FSTYPE_LENGTH);
        else
                login->fstype[0] = '\0';
}
