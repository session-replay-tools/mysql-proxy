%token_prefix TK_

%token_type {token_t}
%default_type {token_t}

%extra_argument {struct network_mysqld_con *con}

%syntax_error {
  UNUSED_PARAMETER(yymajor);  /* Silence some compiler warnings */
  admin_syntax_error(con);
}

%stack_overflow {
  admin_stack_overflow(con);
}

%name adminParser

%include {
#include <assert.h>
#include <inttypes.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include "admin-parser.y.h"
#include "admin-commands.h"

struct network_mysqld_con;

#define UNUSED_PARAMETER(x) (void)(x)
#define YYNOERRORRECOVERY 1
#define YYPARSEFREENEVERNULL 1
#define YYMALLOCARGTYPE  uint64_t

typedef struct equation_t {
  token_t left;
  token_t right;
} equation_t;

static int64_t token2int(token_t token)
{
    /*TODO: HEX*/
    int64_t value = 0;
    int sign = 1;
    const char* c = token.z;
    int i = 0;
    if( *c == '+' || *c == '-' ) {
        if( *c == '-' ) sign = -1;
        c++;
        i++;
    }
    while (isdigit(*c) && i++ < token.n) {
        value *= 10;
        value += (int) (*c-'0');
        c++;
    }
    return (value * sign);
}

static void string_dequote(char* z)
{
    int quote;
    int i, j;
    if( z==0 ) return;
    quote = z[0];
    switch( quote ){
    case '\'':  break;
    case '"':   break;
    case '`':   break;                /* For MySQL compatibility */
    default:    return;
    }
    for (i=1, j=0; z[i]; i++) {
        if (z[i] == quote) {
            if (z[i+1]==quote) { /*quote escape*/
                z[j++] = quote;
                i++;
            } else {
                z[j++] = 0;
                break;
            }
        } else if (z[i] == '\\') { /* slash escape */
            i++;
            z[j++] = z[i];
        } else {
            z[j++] = z[i];
        }
    }
}

static char* token_strdup(token_t token)
{
    if (token.n == 0)
        return NULL;
    char* s = malloc(token.n + 1);
    memcpy(s, token.z, token.n);
    s[token.n] = '\0';
    string_dequote(s);
    return s;
}

} // end %include

input ::= cmd.

%left OR.
%left AND.
%right NOT.
%left LIKE NE EQ.
%left GT LE LT GE.

%fallback ID
  CONN_DETAILS BACKENDS AT_SIGN REDUCE_CONNS ADD MAINTAIN STATUS
  CONN_NUM BACKEND_NDX RESET CETUS RELOAD
  SAVE SETTINGS SINGLE.

%wildcard ANY.

%type opt_where_user {char*}
%destructor opt_where_user {free($$);}
opt_where_user(A) ::= WHERE USER EQ STRING(E). {A = token_strdup(E);}
opt_where_user(A) ::= . {A = NULL;}

%type equation {equation_t}
equation(A) ::= ID(X) EQ STRING|ID|INTEGER|FLOAT(Y)|ON. {
  A.left = X;
  A.right = Y;
}

// list of [key1, value1, key2, value2, ...]
%type equations_prefix {GList*}
%type equations {GList*}
%destructor equations_prefix { g_list_free_full($$, free); }
%destructor equations { g_list_free_full($$, free); }

equations_prefix(A) ::= equations(A) COMMA.
equations_prefix(A) ::= . {A = NULL;}

equations(A) ::= equations_prefix(X) equation(Y). {
  A = g_list_append(X, token_strdup(Y.left));
  A = g_list_append(A, token_strdup(Y.right));
}

%type opt_like {char*}
%destructor opt_like {free($$);}
opt_like(A) ::= LIKE STRING(X). {A = token_strdup(X);}
opt_like(A) ::= . {A = NULL; }

%type boolean {int}
boolean(A) ::= TRUE. {A = 1;}
boolean(A) ::= FALSE. {A = 0;}
boolean(A) ::= INTEGER(X). {A = token2int(X)==0 ? 0:1;}

%type opt_integer {int}
opt_integer(A) ::= . {A = -1;}
opt_integer(A) ::= INTEGER(X). {A = token2int(X);}

%token_class ids STRING|ID.

cmd ::= compatible_cmd SEMI. {
  admin_compatible_cmd(con);
}
compatible_cmd ::= SET NAMES ID.

compatible_cmd ::= USE ID.

cmd ::= SHOW DATABASES SEMI. {
  admin_show_databases(con);
}
cmd ::= SELECT CONN_DETAILS FROM BACKENDS SEMI. {
  admin_select_conn_details(con);
}
cmd ::= SELECT STAR FROM BACKENDS SEMI. {
  admin_select_all_backends(con);
}
cmd ::= SHOW CONNECTIONLIST opt_integer(X) SEMI. {
  admin_show_connectionlist(con, X);
}
cmd ::= SHOW ALLOW_IP SEMI. {
  admin_acl_show_rules(con, TRUE);
}
cmd ::= ADD ALLOW_IP STRING(Y) SEMI. {
  char* ip = token_strdup(Y);
  admin_acl_add_rule(con, TRUE, ip);
  free(ip);
}
cmd ::= DELETE ALLOW_IP STRING(Y) SEMI. {
  char* ip = token_strdup(Y);
  admin_acl_delete_rule(con, TRUE, ip);
  free(ip);
}
cmd ::= SHOW DENY_IP SEMI. {
  admin_acl_show_rules(con, FALSE);
}
cmd ::= ADD DENY_IP STRING(Y) SEMI. {
  char* ip = token_strdup(Y);
  admin_acl_add_rule(con, FALSE, ip);
  free(ip);
}
cmd ::= DELETE DENY_IP STRING(Y) SEMI. {
  char* ip = token_strdup(Y);
  admin_acl_delete_rule(con, FALSE, ip);
  free(ip);
}
cmd ::= SET REDUCE_CONNS boolean(X) SEMI. {
  admin_set_reduce_conns(con, X);
}
cmd ::= SET MAINTAIN boolean(X) SEMI. {
  admin_set_maintain(con, X);
}
cmd ::= SET CHARSET_CHECK boolean(X) SEMI. {
  admin_set_charset_check(con, X);
}
cmd ::= REFRESH_CONNS SEMI. {
  admin_set_server_conn_refresh(con);
}
cmd ::= SHOW MAINTAIN STATUS SEMI. {
  admin_show_maintain(con);
}
cmd ::= SHOW VARIABLES opt_like(X) SEMI. {
  admin_show_variables(con, X);
  if (X) free(X);
}
cmd ::= SELECT VERSION SEMI. {
  admin_select_version(con);
}
cmd ::= SELECT CONN_NUM FROM BACKENDS WHERE BACKEND_NDX EQ INTEGER(X) AND USER EQ STRING(Y) SEMI. {
  char* user = token_strdup(Y);
  admin_select_connection_stat(con, token2int(X), user);
  free(user);
}
cmd ::= SELECT STAR FROM USER_PWD|APP_USER_PWD(T) opt_where_user(X) SEMI. {
  char* table = (@T == TK_USER_PWD)?"user_pwd":"app_user_pwd";
  admin_select_user_password(con, table, X);
  if (X) free(X);
}
cmd ::= UPDATE USER_PWD|APP_USER_PWD(T) SET PASSWORD EQ STRING(P) WHERE USER EQ STRING(U) SEMI. {
  char* table = (@T == TK_USER_PWD)?"user_pwd":"app_user_pwd";
  char* user = token_strdup(U);
  char* pass = token_strdup(P);
  admin_update_user_password(con, table, user, pass);
  free(user);
  free(pass);
}
cmd ::= DELETE FROM USER_PWD|APP_USER_PWD WHERE USER EQ STRING(U) SEMI. {
  char* user = token_strdup(U);
  admin_delete_user_password(con, user);
  free(user);
}
cmd ::= INSERT INTO BACKENDS VALUES LP STRING(X) COMMA STRING(Y) COMMA STRING(Z) RP SEMI. {
  char* addr = token_strdup(X);
  char* type = token_strdup(Y);
  char* state = token_strdup(Z);
  admin_insert_backend(con, addr, type, state);
  free(addr); free(type); free(state);
}
cmd ::= UPDATE BACKENDS SET equations(X) WHERE equation(Z) SEMI. {
  char* cond_key = token_strdup(Z.left);
  char* cond_val = token_strdup(Z.right);
  admin_update_backend(con, X, cond_key, cond_val);
  free(cond_key); free(cond_val);
  g_list_free_full(X, free);
}
cmd ::= DELETE FROM BACKENDS WHERE equation(Z) SEMI. {
  char* key = token_strdup(Z.left);
  char* val = token_strdup(Z.right);
  admin_delete_backend(con, key, val);
  free(key);
  free(val);
}
cmd ::= ADD MASTER STRING(X) SEMI. {
  char* addr = token_strdup(X);
  admin_insert_backend(con, addr, "rw", "unknown");
  free(addr);
}
cmd ::= ADD SLAVE STRING(X) SEMI. {
  char* addr = token_strdup(X);
  admin_insert_backend(con, addr, "ro", "unknown");
  free(addr);
}
cmd ::= STATS GET opt_id(X) SEMI. {
  admin_get_stats(con, X);
  if (X) free(X);
}
cmd ::= CONFIG GET opt_id(X) SEMI. {
  admin_get_config(con, X);
  if (X) free(X);
}
cmd ::= CONFIG SET equation(X) SEMI. {
  char* key = token_strdup(X.left);
  char* val = token_strdup(X.right);
  admin_set_config(con, key, val);
  free(key);
  free(val);
}
cmd ::= CONFIG RELOAD SEMI. {
  admin_config_reload(con, 0);
}
cmd ::= CONFIG RELOAD USER SEMI. {
  admin_config_reload(con, "user");
}
cmd ::= CONFIG RELOAD VARIABLES SEMI. {
  admin_config_reload(con, "variables");
}
cmd ::= SAVE SETTINGS SEMI. {
  admin_save_settings(con);
}
cmd ::= STATS RESET SEMI. {
  admin_reset_stats(con);
}
cmd ::= SELECT STAR FROM HELP SEMI. {
  admin_select_help(con);
}
cmd ::= SELECT HELP SEMI. {
  admin_select_help(con);
}
cmd ::= CETUS SEMI. {
  admin_send_overview(con);
}

%type opt_id {char*}
%destructor opt_id {free($$);}
opt_id(A) ::= ID(X). { A = token_strdup(X); }
opt_id(A) ::= . {A=0;}

cmd ::= SQL LOG STATUS SEMI. {
  admin_sql_log_status(con);
}
cmd ::= SQL LOG START SEMI. {
  admin_sql_log_start(con);
}
cmd ::= SQL LOG STOP SEMI. {
  admin_sql_log_stop(con);
}
cmd ::= STARTCOM ENDCOM SEMI. {
  admin_comment_handle(con);
}
cmd ::= SELECT GLOBAL VERSION_COMMENT LIMIT INTEGER SEMI. {
  admin_select_version_comment(con);
}
cmd ::= REMOVE BACKEND INTEGER(X) SEMI. {
  char* val = token_strdup(X);
  admin_delete_backend(con, "backend_ndx", val);
  free(val);
}
cmd ::=REMOVE BACKEND WHERE equation(Z) SEMI. {
  char* key = token_strdup(Z.left);
  char* val = token_strdup(Z.right);
  admin_delete_backend(con, key, val);
  free(key);
  free(val);
}
