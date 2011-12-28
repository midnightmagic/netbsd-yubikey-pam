#include <sys/param.h>

#include <pwd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define PAM_SM_AUTH
#define PAM_SM_ACCOUNT
#define PAM_SM_SESSION
#define PAM_SM_PASSWORD

#include <security/pam_modules.h>
#include <security/pam_appl.h>
#include <security/openpam.h>

#include "ykclient.h"

#ifndef PAM_EXTERN
#define PAM_EXTERN
#endif

#define D(...) openpam_log(PAM_LOG_DEBUG, __VA_ARGS__)

#define TOKEN_OTP_LEN 32
#define MAX_TOKEN_ID_LEN 16
#define DEFAULT_TOKEN_ID_LEN 12

enum key_mode {
	CHRESP,
	CLIENT
};

struct cfg
{
	int client_id;
	const char *client_key;
	int debug;
	int alwaysok;
	int verbose_otp;
	int try_first_pass;
	int use_first_pass;
	const char *auth_file;
	const char *capath;
	const char *url;
	const char *user_attr;
	const char *yubi_attr;
	int token_id_length;
	enum key_mode mode;
	const char *chalresp_path;
};

extern int _openpam_debug;

static void
parse_cfg (int flags, int argc, const char **argv, struct cfg *cfg)
{
	int i;
	memset (cfg, 0, sizeof(struct cfg));
	cfg->client_id = -1;
	cfg->token_id_length = DEFAULT_TOKEN_ID_LEN;
	cfg->mode = CLIENT;

	for (i = 0; i < argc; i++) {
		if (strncmp (argv[i], "id=", 3) == 0)
			sscanf (argv[i], "id=%d", &cfg->client_id);
		if (strncmp (argv[i], "key=", 4) == 0)
			cfg->client_key = argv[i] + 4;
		if (strcmp (argv[i], "debug") == 0) {
			cfg->debug = 1;
			_openpam_debug=1;
		}
		if (strcmp (argv[i], "alwaysok") == 0)
			cfg->alwaysok = 1;
		if (strcmp (argv[i], "verbose_otp") == 0)
			cfg->verbose_otp = 1;
		if (strcmp (argv[i], "try_first_pass") == 0)
			cfg->try_first_pass = 1;
		if (strcmp (argv[i], "use_first_pass") == 0)
			cfg->use_first_pass = 1;
		if (strncmp (argv[i], "authfile=", 9) == 0)
			cfg->auth_file = argv[i] + 9;
		if (strncmp (argv[i], "capath=", 7) == 0)
			cfg->capath = argv[i] + 7;
		if (strncmp (argv[i], "url=", 4) == 0)
			cfg->url = argv[i] + 4;
		if (strncmp (argv[i], "user_attr=", 10) == 0)
			cfg->user_attr = argv[i] + 10;
		if (strncmp (argv[i], "yubi_attr=", 10) == 0)
			cfg->yubi_attr = argv[i] + 10;
		if (strncmp (argv[i], "token_id_length=", 16) == 0)
			sscanf (argv[i], "token_id_length=%d", &cfg->token_id_length);
		if (strcmp (argv[i], "mode=client") == 0)
			cfg->mode = CLIENT;
	}
	if (cfg->debug) {
		D("called.");
		D("flags %d argc %d", flags, argc);
		for (i = 0; i < argc; i++)
			D("argv[%d]=%s", i, argv[i]);
		D("id=%d", cfg->client_id);
		D("key=%s", cfg->client_key ? cfg->client_key : "(null)");
		D("debug=%d", cfg->debug);
		D("alwaysok=%d", cfg->alwaysok);
		D("verbose_otp=%d", cfg->verbose_otp);
		D("try_first_pass=%d", cfg->try_first_pass);
		D("use_first_pass=%d", cfg->use_first_pass);
		D("authfile=%s", cfg->auth_file ? cfg->auth_file : "(null)");
		D("user_attr=%s", cfg->user_attr ? cfg->user_attr : "(null)");
		D("yubi_attr=%s", cfg->yubi_attr ? cfg->yubi_attr : "(null)");
		D("url=%s", cfg->url ? cfg->url : "(null)");
		D("capath=%s", cfg->capath ? cfg->capath : "(null)");
		D("token_id_length=%d", cfg->token_id_length);
		D("mode=%s", cfg->mode == CLIENT ? "client" : "chresp" );
	}

}

PAM_EXTERN int
pam_sm_authenticate(pam_handle_t *pamh, int flags,
	int argc, const char *argv[])
{
	struct passwd *pwd;
	const char *user;
	char *password;
	int pwd_len;
	int pam_err, retry;
//	int r;
	struct cfg cfg;
	ykclient_t *ykc = NULL;
	int r;
	char otp[MAX_TOKEN_ID_LEN + TOKEN_OTP_LEN + 1] = { 0 };
	char otp_id[MAX_TOKEN_ID_LEN + 1] = { 0 };
    
	/* First, retrieve config data in argv */
	parse_cfg(flags, argc, argv, &cfg);

	/* identify user */
	if ((pam_err = pam_get_user(pamh, &user, NULL)) != PAM_SUCCESS)
		return (pam_err);
	if ((pwd = getpwnam(user)) == NULL)
		return (PAM_USER_UNKNOWN);

	/* get password */
	password = NULL;
	for (retry = 0; retry < 3; ++retry) {
		pam_err = pam_get_authtok(pamh, PAM_AUTHTOK,
			(const char **)&password, NULL);
		if (pam_err == PAM_SUCCESS)
			break;
	}
	if (pam_err == PAM_CONV_ERR)
		return (pam_err);
	if (pam_err != PAM_SUCCESS)
		return (PAM_AUTH_ERR);

	if (password != NULL) {
		D("password token: %s", password);
	} else {
		return(PAM_AUTH_ERR);
	}

	r=ykclient_init (&ykc);
	if (r != YKCLIENT_OK) {
		D("ykclient_init() failed (%d): %s", r, ykclient_strerror(r));
		goto done;
	}

	r=ykclient_set_client_b64 (ykc, cfg.client_id, cfg.client_key);
	if (r != YKCLIENT_OK) {
		D("ykclient_set_client_b64() failed (%d): %s",
			r, ykclient_strerror (r));
		pam_err = PAM_AUTHINFO_UNAVAIL;
		goto done;
	}

	if (cfg.client_key)
		ykclient_set_verify_signature(ykc, 1);
	if (cfg.capath)
		ykclient_set_ca_path(ykc, cfg.capath);
	if (cfg.url)
		ykclient_set_url_template(ykc, cfg.url);

	pwd_len=strlen(password);
	if (pwd_len < (cfg.token_id_length + TOKEN_OTP_LEN)) {
		D("OTP too short to be considered: %i < %i", pwd_len, (cfg.token_id_length+TOKEN_OTP_LEN));
		pam_err=PAM_AUTH_ERR;
		goto done;
	}

	/* Copy full YubiKey output (public ID + OTP) into otp */
	strncpy (otp, password, sizeof (otp) - 1);  
	/* Copy only public ID into otp_id. Destination buffer is zeroed. */
	strncpy (otp_id, password, cfg.token_id_length);

	D("OTP: %s ID: %s ", otp, otp_id);

	r=ykclient_request(ykc, otp);

	D("made it past the ykc init..");

	switch(r) {
		case YKCLIENT_OK:
			break;
		case YKCLIENT_BAD_OTP:
		case YKCLIENT_REPLAYED_OTP:
			pam_err=PAM_AUTH_ERR;
			goto done;
		default:
			pam_err=PAM_AUTHINFO_UNAVAIL;
			goto done;
	}


/*	r=ykclient_verify_otp_v2 (NULL, password, cfg.client_id, NULL, 1,
		(const char **) &cfg.url, cfg.client_key);
	if (r != YKCLIENT_OK)
		pam_err = PAM_AUTH_ERR;
	else
		pam_err = PAM_SUCCESS;*/

/*	if (strcmp("lemmein", password) == 0) {
		pam_err = PAM_SUCCESS;
	} else {
		pam_err = PAM_AUTH_ERR;
	}*/

done:
	if (ykc)
		ykclient_done(&ykc);

	return (pam_err);
}

PAM_EXTERN int
pam_sm_setcred(pam_handle_t *pamh, int flags,
	int argc, const char *argv[])
{
	struct cfg cfg;
	parse_cfg(flags, argc, argv, &cfg);

	if (flags&PAM_ESTABLISH_CRED) {
		if (cfg.debug)
			openpam_log(PAM_LOG_DEBUG, "Establishing cred..");
	} else if (flags&PAM_DELETE_CRED) {
		if (cfg.debug)
			openpam_log(PAM_LOG_DEBUG, "Deleting cred..");
	} else if (flags&PAM_REFRESH_CRED) {
		if (cfg.debug)
			openpam_log(PAM_LOG_DEBUG, "Refreshing cred..");
	}

	return (PAM_SUCCESS);
}

PAM_EXTERN int
pam_sm_acct_mgmt(pam_handle_t *pamh, int flags,
	int argc, const char *argv[])
{

	return (PAM_SUCCESS);
}

PAM_EXTERN int
pam_sm_open_session(pam_handle_t *pamh, int flags,
	int argc, const char *argv[])
{

	return (PAM_SUCCESS);
}

PAM_EXTERN int
pam_sm_close_session(pam_handle_t *pamh, int flags,
	int argc, const char *argv[])
{
	

	return (PAM_SUCCESS);
}

PAM_EXTERN int
pam_sm_chauthtok(pam_handle_t *pamh, int flags,
	int argc, const char *argv[])
{
	struct cfg cfg;
	parse_cfg(flags, argc, argv, &cfg);

	if (cfg.debug)
		openpam_log(PAM_LOG_NOTICE, "Attempted to use non-chauthtok module to change an authentication token");

	return (PAM_SERVICE_ERR);
}

#ifdef PAM_MODULE_ENTRY
PAM_MODULE_ENTRY("pam_yubi");
#endif

