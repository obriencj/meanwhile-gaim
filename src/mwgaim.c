
/*
  Meanwhile Gaim Protocol Plugin (prpl).
  Adds Lotus Sametime support to Gaim.

  Copyright (C) 2004 Christopher (siege) O'Brien <siege@preoccupied.net>
  
  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or (at
  your option) any later version.
  
  This program is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  General Public License for more details.
  
  You should have received a copy of the GNU General Public License
  along with this program; if not, write to the Free Software
  Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307,
  USA.
*/

#include <gaim.h>
#include <accountopt.h>
#include <conversation.h>
#include <debug.h>
#include <internal.h>
#include <notify.h>
#include <plugin.h>
#include <prpl.h>
#include <request.h>
#include <util.h>
#include <version.h>

#include <glib.h>
#include <glib/ghash.h>
#include <glib/glist.h>

#include <mw_cipher.h>
#include <mw_common.h>
#include <mw_error.h>
#include <mw_service.h>
#include <mw_session.h>
#include <mw_srvc_aware.h>
#include <mw_srvc_conf.h>
#include <mw_srvc_im.h>
#include <mw_srvc_resolve.h>
#include <mw_srvc_store.h>
#include <mw_st_list.h>


/* considering that there's no display of this information for prpls,
   I don't know why I even bother providing these. Oh valiant reader,
   I do it all for you. */
#define PLUGIN_ID        "prpl-meanwhile"
#define PLUGIN_NAME      "Meanwhile"
#define PLUGIN_SUMMARY   "Meanwhile Protocol Plugin"
#define PLUGIN_DESC      "Open implementation of a Lotus Sametime client"
#define PLUGIN_AUTHOR    "Christopher (siege) O'Brien <siege@preoccupied.net>"
#define PLUGIN_HOMEPAGE  "http://meanwhile.sf.net/"


/* plugin preference names */
#define MW_PRPL_OPT_BASE          "/plugins/prpl/meanwhile"
#define MW_PRPL_OPT_BLIST_ACTION  MW_PRPL_OPT_BASE "/blist_action"


/* stages of connecting-ness */
#define MW_CONNECT_STEPS  9


/* stages of conciousness */
#define MW_STATE_OFFLINE  _("Offline")
#define MW_STATE_ACTIVE   _("Active")
#define MW_STATE_AWAY     _("Away")
#define MW_STATE_BUSY     _("Do Not Disturb")
#define MW_STATE_IDLE     _("Idle")
#define MW_STATE_UNKNOWN  _("Unknown")
#define MW_STATE_ENLIGHTENED  _("Buddha")


/* keys to get/set chat information */
#define CHAT_KEY_CREATOR  "chat.creator"
#define CHAT_KEY_NAME     "chat.name"
#define CHAT_KEY_TOPIC    "chat.topic"
#define CHAT_KEY_INVITE   "chat.invite"


#define BUDDY_KEY_CLIENT  "buddy.client"


/* keys to get/set gaim plugin information */
#define MW_KEY_HOST        "server"
#define MW_KEY_PORT        "port"
#define MW_KEY_ACTIVE_MSG  "active_msg"


#ifndef PLUGIN_DEFAULT_ACTIVE_MSG
#define PLUGIN_DEFAULT_ACTIVE_MSG  "Talk to me"
#endif


/** default host for the gaim plugin. You can specialize a build to
    default to your server by supplying this at compile time */
#ifndef PLUGIN_DEFAULT_HOST
#define PLUGIN_DEFAULT_HOST  ""
#endif


/** default port for the gaim plugin. You can specialize a build to
    default to your server by supplying this at compile time */
#ifndef PLUGIN_DEFAULT_PORT
#define PLUGIN_DEFAULT_PORT  1533
#endif


/** the amount of data the plugin will attempt to read from a socket
    in a single call */
#define READ_BUFFER_SIZE  1024


/** number of seconds from the first blist change before a save to the
    storage service occurs. */
#define BLIST_SAVE_SECONDS  15


/** blist storage option, local only */
#define BLIST_CHOICE_NONE  1

/** blist storage option, load from server */
#define BLIST_CHOICE_LOAD  2

/** blist storage option, load and save to server */
#define BLIST_CHOICE_SAVE  3


/* testing for the above */
#define BLIST_CHOICE_IS(n) (gaim_prefs_get_int(MW_PRPL_OPT_BLIST_ACTION)==(n))
#define BLIST_CHOICE_IS_NONE() BLIST_CHOICE_IS(BLIST_CHOICE_NONE)
#define BLIST_CHOICE_IS_LOAD() BLIST_CHOICE_IS(BLIST_CHOICE_LOAD)
#define BLIST_CHOICE_IS_SAVE() BLIST_CHOICE_IS(BLIST_CHOICE_SAVE)


/** warning text placed next to plugin option */
#define BLIST_WARNING \
  ("Please note:\n" \
   "The 'load and save' option above is still" \
   " experimental, and highly volatile. Back up" \
   " your buddy list with an official client before" \
   " enabling. Loading takes effect at login.")


/* debugging output */
#define DEBUG_ERROR(a...)  gaim_debug_error(G_LOG_DOMAIN, a)
#define DEBUG_INFO(a...)   gaim_debug_info(G_LOG_DOMAIN, a)
#define DEBUG_MISC(a...)   gaim_debug_misc(G_LOG_DOMAIN, a)
#define DEBUG_WARN(a...)   gaim_debug_warning(G_LOG_DOMAIN, a)


#ifndef NSTR
# define NSTR(str) ((str)? (str): "(null)")
#endif


/** the gaim plugin data.
    available as gc->proto_data and mwSession_getClientData */
struct mwGaimPluginData {
  struct mwSession *session;

  struct mwServiceAware *srvc_aware;
  struct mwServiceConference *srvc_conf;
  struct mwServiceDir *srvc_dir;
  struct mwServiceIm *srvc_im;
  struct mwServiceResolve *srvc_resolve;
  struct mwServiceStorage *srvc_store;

  /** map of GaimGroup:mwAwareList */
  GHashTable *group_map;

  /** event id for the save callback */
  guint save_event;

  /** socket fd */
  int socket;

  GaimConnection *gc;
};


/** resolves a mwSession from a GaimConnection */
static struct mwSession *gc_to_session(GaimConnection *gc) {
  struct mwGaimPluginData *pd;

  g_return_val_if_fail(gc != NULL, NULL);

  pd = gc->proto_data;
  g_return_val_if_fail(pd != NULL, NULL);

  return pd->session;
}


/** resolves a GaimConnection from a mwSession */
static GaimConnection *session_to_gc(struct mwSession *session) {
  struct mwGaimPluginData *pd;

  g_return_val_if_fail(session != NULL, NULL);

  pd = mwSession_getClientData(session);
  g_return_val_if_fail(pd != NULL, NULL);

  return pd->gc;
}


static int mw_session_io_write(struct mwSession *session,
			       const char *buf, gsize len) {
  struct mwGaimPluginData *pd;
  int ret = 0;

  pd = mwSession_getClientData(session);

  /* socket was already closed. */
  if(pd->socket == 0)
    return 1;

  while(len) {
    ret = write(pd->socket, buf, len);
    if(ret <= 0) break;
    len -= ret;
  }

  if(len > 0) {
    DEBUG_ERROR("mw_session_io_write returning %i\n", ret);
    gaim_connection_error(pd->gc, "Connection closed (writing)");
    close(pd->socket);
    pd->socket = 0;
    return -1;
  }

  return 0;
}


static void mw_session_io_close(struct mwSession *session) {
  struct mwGaimPluginData *pd;

  pd = mwSession_getClientData(session);
  if(pd->socket) {
    close(pd->socket);
    pd->socket = 0;
  }
}


static void mw_session_clear(struct mwSession *session) {
  ; /* nothing for now */
}


static GaimGroup *ensure_group(GaimConnection *gc,
			       struct mwSametimeGroup *stgroup) {
  GaimGroup *group;
  const char *name = mwSametimeGroup_getName(stgroup);

  group = gaim_find_group(name);
  if(! group) {
    group = gaim_group_new(name);
    gaim_blist_add_group(group, NULL);
  }

  return group;
}


static GaimBuddy *ensure_buddy(GaimConnection *gc, GaimGroup *group,
			       struct mwSametimeUser *stuser) {
  GaimBuddy *buddy;
  GaimAccount *acct = gaim_connection_get_account(gc);

  const char *id = mwSametimeUser_getUser(stuser);
  const char *name = mwSametimeUser_getShortName(stuser);
  const char *alias = mwSametimeUser_getAlias(stuser);

  buddy = gaim_find_buddy_in_group(acct, id, group);
  if(! buddy) {
    buddy = gaim_buddy_new(acct, id, alias);
    buddy->server_alias = g_strdup(name);
  
    gaim_blist_add_buddy(buddy, NULL, group, NULL);

    /* why doesn't the above trigger this? need to let meanwhile know
       about these buddies. */
    serv_add_buddy(gc, buddy);

  } else {
    gaim_blist_alias_buddy(buddy, alias);
    buddy->server_alias = g_strdup(name);
  }

  return buddy;
}


static void import_blist(GaimConnection *gc, struct mwSametimeList *stlist) {
  struct mwSametimeGroup *stgroup;
  struct mwSametimeUser *stuser;

  GaimGroup *group;
  GaimBuddy *buddy;

  GList *gl, *gtl, *ul, *utl;

  /* check our preferences for loading */
  if(BLIST_CHOICE_IS_NONE()) {
    DEBUG_INFO("preferences indicate not to load remote buddy list\n");
    return;
  }

  gl = gtl = mwSametimeList_getGroups(stlist);
  for(; gl; gl = gl->next) {

    stgroup = (struct mwSametimeGroup *) gl->data;
    group = ensure_group(gc, stgroup);

    ul = utl = mwSametimeGroup_getUsers(stgroup);
    for(; ul; ul = ul->next) {

      stuser = (struct mwSametimeUser *) ul->data;
      buddy = ensure_buddy(gc, group, stuser);
    }
    g_list_free(utl);
  }
  g_list_free(gtl);
}


static void fetch_blist_cb(struct mwServiceStorage *srvc,
			   guint32 result, struct mwStorageUnit *item,
			   gpointer data) {

  struct mwGaimPluginData *pd = data;
  struct mwSametimeList *stlist;
  struct mwSession *s;

  struct mwGetBuffer *b;

  g_return_if_fail(result == ERR_SUCCESS);

  b = mwGetBuffer_wrap(mwStorageUnit_asOpaque(item));

  stlist = mwSametimeList_new();
  mwSametimeList_get(b, stlist);

  s = mwService_getSession(MW_SERVICE(srvc));
  import_blist(pd->gc, stlist);

  mwSametimeList_free(stlist);
}


static void fetch_blist(struct mwGaimPluginData *pd) {
  struct mwServiceStorage *srvc;
  struct mwStorageUnit *unit;

  srvc = pd->srvc_store;
  unit = mwStorageUnit_new(mwStore_AWARE_LIST);
  mwServiceStorage_load(srvc, unit, fetch_blist_cb, pd, NULL);
}


static void mw_session_stateChange(struct mwSession *session,
				   enum mwSessionState state, guint32 info) {
  struct mwGaimPluginData *pd;
  GaimConnection *gc;
  char *msg = NULL;

  pd = mwSession_getClientData(session);
  gc = pd->gc;

  switch(state) {
  case mwSession_STARTING:
    msg = _("Sending Handshake");
    gaim_connection_update_progress(gc, msg, 2, MW_CONNECT_STEPS);
    break;

  case mwSession_HANDSHAKE:
    msg = _("Waiting for Handshake Acknowledgement");
    gaim_connection_update_progress(gc, msg, 3, MW_CONNECT_STEPS);
    break;

  case mwSession_HANDSHAKE_ACK:
    msg = _("Handshake Acknowledged, Sending Login");
    gaim_connection_update_progress(gc, msg, 4, MW_CONNECT_STEPS);
    break;

  case mwSession_LOGIN:
    msg = _("Waiting for Login Acknowledgement");
    gaim_connection_update_progress(gc, msg, 5, MW_CONNECT_STEPS);
    break;

  case mwSession_LOGIN_REDIR:
    msg = _("Login Redirected");
    gaim_connection_update_progress(gc, msg, 6, MW_CONNECT_STEPS);
    break;

  case mwSession_LOGIN_ACK:
    msg = _("Login Acknowledged");
    gaim_connection_update_progress(gc, msg, 7, MW_CONNECT_STEPS);
    break;

  case mwSession_STARTED:
    msg = _("Connected to Sametime Community Server");
    gaim_connection_update_progress(gc, msg, 8, MW_CONNECT_STEPS);
    gaim_connection_set_state(gc, GAIM_CONNECTED);
    serv_finish_login(gc);
    serv_set_away(gc, MW_STATE_ACTIVE, NULL);
    fetch_blist(pd);
    break;

  case mwSession_STOPPING:
    if(info & ERR_FAILURE) {
      msg = mwError(info);
      gaim_connection_error(gc, msg);
      g_free(msg);
    }
    break;

  case mwSession_STOPPED:
    break;

  case mwSession_UNKNOWN:
  default:
    DEBUG_WARN("session in unknown state");
  }
}


static void mw_session_setPrivacyInfo(struct mwSession *session) {
  ;
}


static void mw_session_setUserStatus(struct mwSession *session) {
  struct mwGaimPluginData *pd;
  GaimConnection *gc;
  struct mwAwareIdBlock idb = { mwAware_USER, NULL, NULL };
  struct mwUserStatus *stat;

  g_return_if_fail(session != NULL);

  pd = mwSession_getClientData(session);
  g_return_if_fail(pd != NULL);

  gc = pd->gc;
  g_return_if_fail(gc != NULL);

  idb.user = mwSession_getProperty(session, PROPERTY_SESSION_USER_ID);
  stat = mwSession_getUserStatus(session);

  mwServiceAware_setStatus(pd->srvc_aware, &idb, stat);
}


static void mw_session_admin(struct mwSession *session,
			     const char *text) {

  GaimConnection *gc = session_to_gc(session);
  g_return_if_fail(gc != NULL);

  gaim_notify_message(gc, GAIM_NOTIFY_MSG_INFO, _("Admin Alert"),
		      text, NULL, NULL, NULL);
}


static void read_cb(gpointer data, gint source,
		    GaimInputCondition cond) {

  struct mwGaimPluginData *pd = data;

  g_return_if_fail(pd != NULL);

  if(cond & GAIM_INPUT_READ) {
    char buf[READ_BUFFER_SIZE];
    int len = READ_BUFFER_SIZE;

    len = read(pd->socket, buf, len);
    if(len > 0) {
      DEBUG_INFO("read %u bytes\n", len);
      mwSession_recv(pd->session, buf, len);
      return;
    }
  }

  /* fall-through indicates error */

  if(pd->socket) {
    close(pd->socket);
    pd->socket = 0;
  }

  if(pd->gc->inpa) {
    gaim_input_remove(pd->gc->inpa);
    pd->gc->inpa = 0;
  }

  gaim_connection_destroy(pd->gc);
}


static void connect_cb(gpointer data, gint source,
		       GaimInputCondition cond) {

  struct mwGaimPluginData *pd = data;
  GaimConnection *gc = pd->gc;

  if(! g_list_find(gaim_connections_get_all(), pd->gc)) {
    close(source);
    g_return_if_reached();
  }

  if(source < 0) {
    gaim_connection_error(pd->gc, "Unable to connect to host");
    return;
  }

  pd->socket = source;
  gc->inpa = gaim_input_add(source, GAIM_INPUT_READ, read_cb, pd);

  mwSession_start(pd->session);
}


static void mw_session_loginRedirect(struct mwSession *session,
				     const char *host) {

  struct mwGaimPluginData *pd;
  GaimConnection *gc;
  GaimAccount *account;
  guint port;

  pd = mwSession_getClientData(session);
  gc = pd->gc;
  account = gaim_connection_get_account(gc);
  port = gaim_account_get_int(account, "port", PLUGIN_DEFAULT_PORT);

  mwSession_stop(session, 0x0);

  if(gaim_proxy_connect(account, host, port, connect_cb, pd)) {
    gaim_connection_error(gc, "Unable to connect to host");
  }
}


static struct mwSessionHandler mw_session_handler = {
  .io_write = mw_session_io_write,
  .io_close = mw_session_io_close,
  .clear = mw_session_clear,
  .on_stateChange = mw_session_stateChange,
  .on_setPrivacyInfo = mw_session_setPrivacyInfo,
  .on_setUserStatus = mw_session_setUserStatus,
  .on_admin = mw_session_admin,
  .on_loginRedirect = mw_session_loginRedirect,
};


static struct mwServiceAware *mw_srvc_aware_new(struct mwSession *s) {
  struct mwServiceAware *srvc;
  srvc = mwServiceAware_new(s);
  return srvc;
};


static void mw_conf_invited(struct mwConference *conf,
			    struct mwLoginInfo *inviter,
			    const char *invitation) {
  
  struct mwServiceConference *srvc;
  struct mwSession *session;
  struct mwGaimPluginData *pd;
  GaimConnection *gc;

  char *c_inviter, *c_name, *c_topic, *c_invitation;
  GHashTable *ht;

  srvc = mwConference_getService(conf);
  session = mwService_getSession(MW_SERVICE(srvc));
  pd = mwSession_getClientData(session);
  gc = pd->gc;

  ht = g_hash_table_new_full(g_str_hash, g_str_equal, NULL, g_free);

  c_inviter = g_strdup(inviter->user_id);
  g_hash_table_insert(ht, CHAT_KEY_CREATOR, c_inviter);

  c_name = g_strdup(mwConference_getName(conf));
  g_hash_table_insert(ht, CHAT_KEY_NAME, c_name);

  c_topic = g_strdup(mwConference_getTitle(conf));
  g_hash_table_insert(ht, CHAT_KEY_TOPIC, c_topic);

  c_invitation = g_strdup(invitation);
  g_hash_table_insert(ht, CHAT_KEY_INVITE, c_invitation);

  DEBUG_INFO("received invitation from '%s' to join ('%s','%s'): '%s'\n",
	     c_inviter, c_name, c_topic, c_invitation);

  serv_got_chat_invite(gc, c_topic, c_inviter, c_invitation, ht);
}


#define CONF_TO_ID(conf)   (GPOINTER_TO_INT(conf))
#define ID_TO_CONF(pd, id) (find_conf_by_id((pd), (id)))

#define CHAT_TO_ID(chat)   (gaim_conv_chat_get_id(chat))
#define ID_TO_CHAT(id)     (gaim_find_chat(id))

#define CHAT_TO_CONF(pd, chat) \
  (ID_TO_CONF((pd), CHAT_TO_ID(chat)))

#define CONF_TO_CHAT(conf) \
  (ID_TO_CHAT(CONF_TO_ID(conf)))


static struct mwConference *
find_conf_by_id(struct mwGaimPluginData *pd, int id) {

  struct mwServiceConference *srvc = pd->srvc_conf;
  struct mwConference *conf = NULL;
  GList *l, *ll;
  
  ll = mwServiceConference_getConferences(srvc);
  for(l = ll; l; l = l->next) {
    struct mwConference *c = l->data;
    GaimConvChat *h = mwConference_getClientData(c);

    if(CHAT_TO_ID(h) == id) {
      conf = c;
      break;
    }
  }
  g_list_free(ll);
  
  return conf;
}


static void mw_conf_opened(struct mwConference *conf, GList *members) {
  struct mwServiceConference *srvc;
  struct mwSession *session;
  struct mwGaimPluginData *pd;
  GaimConnection *gc;
  GaimConversation *g_conf;

  srvc = mwConference_getService(conf);
  session = mwService_getSession(MW_SERVICE(srvc));
  pd = mwSession_getClientData(session);
  gc = pd->gc;

  g_conf = serv_got_joined_chat(gc, CONF_TO_ID(conf),
				mwConference_getTitle(conf));

  mwConference_setClientData(conf, GAIM_CONV_CHAT(g_conf), NULL);

  for(; members; members = members->next) {
    struct mwLoginInfo *peer = members->data;
    gaim_conv_chat_add_user(GAIM_CONV_CHAT(g_conf), peer->user_id,
			    NULL, GAIM_CBFLAGS_NONE, FALSE);
  }
}


static void mw_conf_closed(struct mwConference *conf, guint32 reason) {
  struct mwServiceConference *srvc;
  struct mwSession *session;
  struct mwGaimPluginData *pd;
  GaimConnection *gc;

  srvc = mwConference_getService(conf);
  session = mwService_getSession(MW_SERVICE(srvc));
  pd = mwSession_getClientData(session);
  gc = pd->gc;

  serv_got_chat_left(gc, CONF_TO_ID(conf));

  /* @todo send a GAIM_MESSAGE_ERROR for the reason */
}


static void mw_conf_peer_joined(struct mwConference *conf,
				struct mwLoginInfo *peer) {

  struct mwServiceConference *srvc;
  struct mwSession *session;
  struct mwGaimPluginData *pd;
  GaimConnection *gc;
  GaimConvChat *g_conf;

  srvc = mwConference_getService(conf);
  session = mwService_getSession(MW_SERVICE(srvc));
  pd = mwSession_getClientData(session);
  gc = pd->gc;

  g_conf = mwConference_getClientData(conf);
  g_return_if_fail(g_conf != NULL);

  gaim_conv_chat_add_user(g_conf, peer->user_id,
			  NULL, GAIM_CBFLAGS_NONE, TRUE);
}


static void mw_conf_peer_parted(struct mwConference *conf,
				struct mwLoginInfo *peer) {
  
  struct mwServiceConference *srvc;
  struct mwSession *session;
  struct mwGaimPluginData *pd;
  GaimConnection *gc;
  GaimConvChat *g_conf;

  srvc = mwConference_getService(conf);
  session = mwService_getSession(MW_SERVICE(srvc));
  pd = mwSession_getClientData(session);
  gc = pd->gc;

  g_conf = mwConference_getClientData(conf);
  g_return_if_fail(g_conf != NULL);

  gaim_conv_chat_remove_user(g_conf, peer->user_id, NULL);
}


static void mw_conf_text(struct mwConference *conf,
			 struct mwLoginInfo *who, const char *text) {
  
  struct mwServiceConference *srvc;
  struct mwSession *session;
  struct mwGaimPluginData *pd;
  GaimConnection *gc;
  char *esc;

  srvc = mwConference_getService(conf);
  session = mwService_getSession(MW_SERVICE(srvc));
  pd = mwSession_getClientData(session);
  gc = pd->gc;

  esc = gaim_escape_html(text);
  serv_got_chat_in(gc, CONF_TO_ID(conf), who->user_id, 0, esc, time(NULL));
  g_free(esc);
}


static void mw_conf_typing(struct mwConference *conf,
			   struct mwLoginInfo *who, gboolean typing) {

  /* @todo maybe set the user icon based on typing state */
  ;
}


static void mw_conf_clear(struct mwServiceConference *srvc) {
  ;
}


static struct mwConferenceHandler mw_conference_handler = {
  .on_invited = mw_conf_invited,
  .conf_opened = mw_conf_opened,
  .conf_closed = mw_conf_closed,
  .on_peer_joined = mw_conf_peer_joined,
  .on_peer_parted = mw_conf_peer_parted,
  .on_text = mw_conf_text,
  .on_typing = mw_conf_typing,
  .clear = mw_conf_clear,
};


static struct mwServiceConference *mw_srvc_conf_new(struct mwSession *s) {
  struct mwServiceConference *srvc;
  srvc = mwServiceConference_new(s, &mw_conference_handler);
  return srvc;
}


#if 0
static void mw_dir_book_list(struct mwServiceDirectory *srvc, GList *books) {
  ;
}


static void mw_dir_opened(struct mwDirectory *dir) {
  ;
}


static void mw_dir_closed(struct mwDirectory *dir) {
  ;
}


static void mw_dir_clear(struct mwServiceDirectory *srvc) {
  ;
}


static struct mwDirectoryHandler mw_directory_handler = {
  .on_book_list = mw_dir_book_list,
  .dir_opened = mw_dir_opened,
  .dir_closed = mw_dir_closed,
  .clear = mw_dir_clear,
};


static struct mwServiceDirectory *mw_srvc_dir_new(struct mwSession *s) {
  struct mwServiceDirectory *srvc;
  srvc = mwServiceDirectory_new(s, &mw_directory_handler);
  return srvc;
}
#endif


struct convo_msg {
  enum mwImSendType type;
  gpointer data;
  GDestroyNotify clear;
};


struct convo_data {
  struct mwConversation *conv;
  GList *queue;
};


static void convo_data_free(struct convo_data *cd) {
  GList *l = cd->queue;
  for(; l; l = g_list_delete_link(l, l)) {
    struct convo_msg *m = l->data;
    if(m->clear) m->clear(m->data);
    g_free(m);
  }
  g_free(cd);
}


static void convo_data_new(struct mwConversation *conv) {
  struct convo_data *cd;

  g_return_if_fail(conv != NULL);

  if(mwConversation_getClientData(conv))
    return;

  cd = g_new0(struct convo_data, 1);
  cd->conv = conv;

  mwConversation_setClientData(conv, cd, (GDestroyNotify) convo_data_free);
}


static void convo_queue(struct mwConversation *conv,
			enum mwImSendType type, gconstpointer data) {

  struct convo_data *cd;
  struct convo_msg *m;

  convo_data_new(conv);
  cd = mwConversation_getClientData(conv);

  m = g_new0(struct convo_msg, 1);
  m->type = type;

  switch(type) {
  case mwImSend_PLAIN:
    m->data = g_strdup((char *) data);
    m->clear = g_free;
    break;
    
  case mwImSend_TYPING:
  default:
    m->data = (gpointer) data;
    m->clear = NULL;
  }

  cd->queue = g_list_append(cd->queue, m);
}


static void convo_queue_send(struct mwConversation *conv) {
  struct convo_data *cd;
  GList *l;
  
  cd = mwConversation_getClientData(conv);

  for(l = cd->queue; l; l = g_list_delete_link(l, l)) {
    struct convo_msg *m = l->data;

    mwConversation_send(conv, m->type, m->data);

    if(m->clear) m->clear(m->data);
    g_free(m);
  }

  cd->queue = NULL;
}


static void mw_conversation_opened(struct mwConversation *conv) {
  struct mwServiceIm *srvc;
  struct mwSession *session;
  struct mwGaimPluginData *pd;
  GaimConnection *gc;
  GaimAccount *acct;

  struct convo_dat *cd;

  srvc = mwConversation_getService(conv);
  session = mwService_getSession(MW_SERVICE(srvc));
  pd = mwSession_getClientData(session);
  gc = pd->gc;
  acct = gaim_connection_get_account(gc);

  cd = mwConversation_getClientData(conv);
  if(cd) {
    struct mwIdBlock *idb;
    idb = mwConversation_getTarget(conv);

    convo_queue_send(conv);
  
    if(! gaim_find_conversation_with_account(idb->user, acct))
      mwConversation_close(conv, ERR_SUCCESS);

  } else {
    GaimBuddy *buddy;
    struct mwLoginInfo *info;
    info = mwConversation_getTargetInfo(conv);

    buddy = gaim_find_buddy(acct, info->user_id);
    if(buddy) {
      gaim_blist_node_set_int((GaimBlistNode *) buddy,
			      BUDDY_KEY_CLIENT, info->type);
    }

    convo_data_new(conv);
    /* @todo psychic mode */
  }
}


static void mw_conversation_closed(struct mwConversation *conv,
				   guint32 reason) {

  struct mwServiceIm *srvc;
  struct mwSession *session;
  struct mwGaimPluginData *pd;
  GaimConnection *gc;
  GaimAccount *acct;

  struct convo_data *cd;
  struct mwIdBlock *idb;

  GaimConversation *gconv = NULL;
  char *text = NULL, *tmp = NULL;

  g_return_if_fail(conv != NULL);

  srvc = mwConversation_getService(conv);
  session = mwService_getSession(MW_SERVICE(srvc));
  pd = mwSession_getClientData(session);
  gc = pd->gc;
  acct = gaim_connection_get_account(gc);

  cd = mwConversation_getClientData(conv);
  g_return_if_fail(cd != NULL);

  idb = mwConversation_getTarget(conv);

  if(reason) {
    tmp = mwError(reason);
    text = g_strconcat("Unable to send message: ", tmp, NULL);
    gconv = gaim_find_conversation_with_account(idb->user, acct);
  }

  if(gconv && !gaim_conv_present_error(idb->user, gconv->account, text)) {
    g_free(text);
    text = g_strdup_printf("Unable to send message to %s:",
			   (idb->user)? idb->user: "(unknown)");
    gaim_notify_error(gaim_account_get_connection(gconv->account),
		      NULL, text, tmp);
  }

  g_free(tmp);
  g_free(text);

  mwConversation_removeClientData(conv);
}


static void im_recv_text(struct mwConversation *conv,
			 struct mwGaimPluginData *pd,
			 const char *msg) {

  struct mwIdBlock *idb;
  char *esc;

  idb = mwConversation_getTarget(conv);
  esc = gaim_escape_html(msg);

  serv_got_im(pd->gc, idb->user, esc, 0, time(NULL));
  g_free(esc);
}


static void im_recv_typing(struct mwConversation *conv,
			   struct mwGaimPluginData *pd,
			   gboolean typing) {

  struct mwIdBlock *idb;
  idb = mwConversation_getTarget(conv);

  serv_got_typing(pd->gc, idb->user, 0,
		  typing? GAIM_TYPING: GAIM_NOT_TYPING);
}


static void im_recv_html(struct mwConversation *conv,
			 struct mwGaimPluginData *pd,
			 const char *msg) {

  struct mwIdBlock *idb;
  idb = mwConversation_getTarget(conv);

  serv_got_im(pd->gc, idb->user, msg, 0, time(NULL));
}


static void im_recv_subj(struct mwConversation *conv,
			 struct mwGaimPluginData *pd,
			 const char *subj) {

  /* @todo implement this */
  ;
}


static void im_recv_mime(struct mwConversation *conv,
			 struct mwGaimPluginData *pd,
			 struct mwOpaque *data) {

  /* @todo implement this */
  ;
}


static void mw_conversation_recv(struct mwConversation *conv,
				 enum mwImSendType type,
				 gconstpointer msg) {

  struct mwServiceIm *srvc;
  struct mwSession *session;
  struct mwGaimPluginData *pd;

  srvc = mwConversation_getService(conv);
  session = mwService_getSession(MW_SERVICE(srvc));
  pd = mwSession_getClientData(session);

  switch(type) {
  case mwImSend_PLAIN:
    im_recv_text(conv, pd, msg);
    break;

  case mwImSend_TYPING:
    im_recv_typing(conv, pd, !! msg);
    break;

  case mwImSend_HTML:
    im_recv_html(conv, pd, msg);
    break;

  case mwImSend_SUBJECT:
    im_recv_subj(conv, pd, msg);
    break;

  case mwImSend_MIME:
    im_recv_mime(conv, pd, (struct mwOpaque *) msg);
    break;

  default:
    ; /* erm... */
  }
}


static void mw_im_clear(struct mwServiceIm *srvc) {
  ;
}


static struct mwImHandler mw_im_handler = {
  .conversation_opened = mw_conversation_opened,
  .conversation_closed = mw_conversation_closed,
  .conversation_recv = mw_conversation_recv,
  .clear = mw_im_clear,
};


static struct mwServiceIm *mw_srvc_im_new(struct mwSession *s) {
  struct mwServiceIm *srvc;
  srvc = mwServiceIm_new(s, &mw_im_handler);
  return srvc;
}


static struct mwServiceResolve *mw_srvc_resolve_new(struct mwSession *s) {
  struct mwServiceResolve *srvc;
  srvc = mwServiceResolve_new(s);
  return srvc;
}


static struct mwServiceStorage *mw_srvc_store_new(struct mwSession *s) {
  struct mwServiceStorage *srvc;
  srvc = mwServiceStorage_new(s);
  return srvc;
}


/** allocate and associate a mwGaimPluginData with a GaimConnection */
static struct mwGaimPluginData *mwGaimPluginData_new(GaimConnection *gc) {
  struct mwGaimPluginData *pd;

  g_return_val_if_fail(gc != NULL, NULL);

  pd = g_new0(struct mwGaimPluginData, 1);
  pd->gc = gc;
  pd->session = mwSession_new(&mw_session_handler);
  pd->srvc_aware = mw_srvc_aware_new(pd->session);
  pd->srvc_conf = mw_srvc_conf_new(pd->session);
  pd->srvc_dir = NULL; /* mw_srvc_dir_new(pd->session); */
  pd->srvc_im = mw_srvc_im_new(pd->session);
  pd->srvc_resolve = mw_srvc_resolve_new(pd->session);
  pd->srvc_store = mw_srvc_store_new(pd->session);
  pd->group_map = g_hash_table_new(g_direct_hash, g_direct_equal);

  mwSession_addService(pd->session, MW_SERVICE(pd->srvc_aware));
  mwSession_addService(pd->session, MW_SERVICE(pd->srvc_conf));
  /* mwSession_addService(pd->session, MW_SERVICE(pd->srvc_dir)); */
  mwSession_addService(pd->session, MW_SERVICE(pd->srvc_im));
  mwSession_addService(pd->session, MW_SERVICE(pd->srvc_resolve));
  mwSession_addService(pd->session, MW_SERVICE(pd->srvc_store));

  mwSession_addCipher(pd->session, mwCipher_new_RC2_40(pd->session));

  mwSession_setClientData(pd->session, pd, NULL);
  gc->proto_data = pd;

  return pd;
}


static void mwGaimPluginData_free(struct mwGaimPluginData *pd) {
  g_return_if_fail(pd != NULL);

  pd->gc->proto_data = NULL;

  mwSession_removeService(pd->session, SERVICE_AWARE);
  mwSession_removeService(pd->session, SERVICE_CONFERENCE);
  /* mwSession_removeService(pd->session, SERVICE_DIRECTORY); */
  mwSession_removeService(pd->session, SERVICE_IM);
  mwSession_removeService(pd->session, SERVICE_RESOLVE);
  mwSession_removeService(pd->session, SERVICE_STORAGE);

  mwService_free(MW_SERVICE(pd->srvc_aware));
  mwService_free(MW_SERVICE(pd->srvc_conf));
  /* mwService_free(MW_SERVICE(pd->srvc_dir)); */
  mwService_free(MW_SERVICE(pd->srvc_im));
  mwService_free(MW_SERVICE(pd->srvc_resolve));
  mwService_free(MW_SERVICE(pd->srvc_store));

  mwCipher_free(mwSession_getCipher(pd->session, mwCipher_RC2_40));

  mwSession_free(pd->session);

  g_hash_table_destroy(pd->group_map);

  g_free(pd);
}


static const char *mw_prpl_list_icon(GaimAccount *a, GaimBuddy *b) {
  /* my little green dude is a chopped up version of the aim running
     guy.  First, cut of the head and store someplace safe. Then, take
     the left-half side of the body and throw it away. Make a copy of
     the remaining body, and flip it horizontally. Now attach the two
     pieces into an X shape, and drop the head back on the top, being
     careful to center it. Then, just change the color saturation to
     bring the red down a bit, and voila! */

  /* then, throw all of that away and use sodipodi to make a new
     icon. You know, LIKE A REAL MAN. */

  return "meanwhile";
}


static void mw_prpl_list_emblems(GaimBuddy *b,
				 char **se, char **sw,
				 char **nw, char **ne) {

  if(! GAIM_BUDDY_IS_ONLINE(b)) {
    *se = "offline";
  } else if(b->uc == (mwStatus_AWAY | UC_UNAVAILABLE)) {
    *se = "away";
  } else if(b->uc == (mwStatus_BUSY | UC_UNAVAILABLE)) {
    *se = "dnd";
  }
}


static char *mw_prpl_status_text(GaimBuddy *b) {
  GaimConnection *gc;
  struct mwGaimPluginData *pd;
  struct mwAwareIdBlock t = { mwAware_USER, b->name, NULL };
  const char *ret;

  gc = b->account->gc;
  pd = gc->proto_data;

  ret = mwServiceAware_getText(pd->srvc_aware, &t);
  return (ret)? g_strdup(ret): NULL;
}


static const char *status_text(GaimBuddy *b) {
  guint status = b->uc;

  if(! GAIM_BUDDY_IS_ONLINE(b) ) {
    return MW_STATE_OFFLINE;

  } else if(status == (mwStatus_AWAY | UC_UNAVAILABLE)) {
    return MW_STATE_AWAY;

  } else if(status == (mwStatus_BUSY | UC_UNAVAILABLE)) {
    return MW_STATE_BUSY;

  } else if(status == mwStatus_IDLE) {
    return MW_STATE_IDLE;

  } else if(status == mwStatus_ACTIVE) {
    return MW_STATE_ACTIVE;

  } else {
    return MW_STATE_UNKNOWN;
  }
}


static char *mw_prpl_tooltip_text(GaimBuddy *b) {
  GaimConnection *gc;
  struct mwGaimPluginData *pd;
  struct mwAwareIdBlock t = { mwAware_USER, b->name, NULL };
  const char *stat, *ret;

  gc = b->account->gc;
  pd = gc->proto_data;

  stat = status_text(b);
  ret = mwServiceAware_getText(pd->srvc_aware, &t);

  if(! ret) {
    return g_strconcat("\n<b>Status:</b> ", stat, NULL);
    
  } else {
    return g_strconcat("\n<b>Status:</b> ", stat, "\n"
		       "<b>Message:</b> ", ret, NULL);
  }
}


static GList *mw_prpl_away_states(GaimConnection *gc) {
  GList *l = NULL;
  l = g_list_append(l, MW_STATE_ACTIVE);
  l = g_list_append(l, MW_STATE_AWAY);
  l = g_list_append(l, MW_STATE_BUSY);
  l = g_list_append(l, (char *) GAIM_AWAY_CUSTOM);

  return l;
}


static GList *mw_prpl_blist_node_menu(GaimBlistNode *node) {
  return NULL;
}


static GList *mw_prpl_chat_info(GaimConnection *gc) {
  GList *l = NULL;
  struct proto_chat_entry *pce;
  
  pce = g_new0(struct proto_chat_entry, 1);
  pce->label = "Topic:";
  pce->identifier = CHAT_KEY_TOPIC;
  l = g_list_append(l, pce);
  
  return l;
}


static GHashTable *mw_prpl_chat_info_defaults(GaimConnection *gc,
					      const char *name) {
  return NULL;
}


static void mw_prpl_login(GaimAccount *account) {
  GaimConnection *gc;
  struct mwGaimPluginData *pd;

  char *user, *pass, *host;
  guint port;

  gc = gaim_account_get_connection(account);
  pd = mwGaimPluginData_new(gc);

  user = g_strdup(gaim_account_get_username(account));
  pass = (char *) gaim_account_get_password(account);

  host = strrchr(user, ':');
  if(host) *host++ = '\0';

  if(! host) {
    const char *h;
    char *t;

    h = gaim_account_get_string(account, MW_KEY_HOST, PLUGIN_DEFAULT_HOST);
    if(h) {
      t = g_strdup_printf("%s:%s", user, h);
      gaim_account_set_username(account, t);
      g_free(t);
      host = (char *) h;
    }
  }

  /* host = gaim_account_get_string(account, "server", PLUGIN_DEFAULT_HOST); */
  port = gaim_account_get_int(account, MW_KEY_PORT, PLUGIN_DEFAULT_PORT);

  DEBUG_INFO("user: '%s'\n", user);
  DEBUG_INFO("host: '%s'\n", host);
  DEBUG_INFO("port: %u\n", port);

  mwSession_setProperty(pd->session, PROPERTY_SESSION_USER_ID, user, g_free);
  mwSession_setProperty(pd->session, PROPERTY_SESSION_PASSWORD, pass, NULL);

  gaim_connection_update_progress(gc, "Connecting", 1, MW_CONNECT_STEPS);

  if(gaim_proxy_connect(account, host, port, connect_cb, pd)) {
    gaim_connection_error(gc, "Unable to connect to host");
  }
}


static void export_blist(GaimConnection *gc, struct mwSametimeList *stlist) {
  /* - find the account for this connection
     - iterate through the buddy list
     - add each buddy matching this account to the stlist
  */

  GaimAccount *acct;
  GaimBuddyList *blist;
  GaimBlistNode *gn, *cn, *bn;
  GaimGroup *grp;
  GaimBuddy *bdy;

  struct mwSametimeGroup *stg = NULL;
  struct mwIdBlock idb = { NULL, NULL };

  acct = gaim_connection_get_account(gc);
  g_return_if_fail(acct != NULL);

  blist = gaim_get_blist();
  g_return_if_fail(blist != NULL);

  for(gn = blist->root; gn; gn = gn->next) {
    if(! GAIM_BLIST_NODE_IS_GROUP(gn)) continue;
    grp = (GaimGroup *) gn;

    if(! gaim_group_on_account(grp, acct)) continue;
    stg = mwSametimeGroup_new(stlist, mwSametimeGroup_NORMAL, grp->name);

    for(cn = gn->child; cn; cn = cn->next) {
      if(! GAIM_BLIST_NODE_IS_CONTACT(cn)) continue;

      for(bn = cn->child; bn; bn = bn->next) {
	if(! GAIM_BLIST_NODE_IS_BUDDY(bn)) continue;
	bdy = (GaimBuddy *) bn;

	if(bdy->account == acct) {
	  struct mwSametimeUser *stu;
	  idb.user = bdy->name;
	  stu = mwSametimeUser_new(stg, mwSametimeUser_NORMAL, &idb);
	  mwSametimeUser_setShortName(stu, bdy->server_alias);
	  mwSametimeUser_setAlias(stu, bdy->alias);
	}	
      }
    }
  }  
}


static void blist_store(struct mwGaimPluginData *pd) {

  struct mwSametimeList *stlist;
  struct mwServiceStorage *srvc;
  struct mwStorageUnit *unit;

  GaimConnection *gc;

  struct mwPutBuffer *b;
  struct mwOpaque *o;

  g_return_if_fail(pd != NULL);

  srvc = pd->srvc_store;
  g_return_if_fail(srvc != NULL);

  gc = pd->gc;

  /* check if we should do this, according to user prefs */
  if(! BLIST_CHOICE_IS_SAVE()) {
    DEBUG_INFO("preferences indicate not to save remote blist\n");
    return;
  }

  if(MW_SERVICE_IS_DEAD(srvc)) {
    DEBUG_INFO("aborting save of blist: storage service is not alive\n");
    return;
  }

  stlist = mwSametimeList_new();
  export_blist(gc, stlist);

  b = mwPutBuffer_new();

  mwSametimeList_put(b, stlist);
  mwSametimeList_free(stlist);

  unit = mwStorageUnit_new(mwStore_AWARE_LIST);
  o = mwStorageUnit_asOpaque(unit);

  mwPutBuffer_finalize(o, b);

  mwServiceStorage_save(srvc, unit, NULL, NULL, NULL);
}


static void mw_prpl_close(GaimConnection *gc) {
  struct mwGaimPluginData *pd;

  g_return_if_fail(gc != NULL);

  pd = gc->proto_data;
  g_return_if_fail(pd != NULL);

  mwSession_stop(pd->session, 0x00);

  if(pd->save_event) {
    gaim_timeout_remove(pd->save_event);
    pd->save_event = 0;
    blist_store(pd);
  }

  gc->proto_data = NULL;

  if(gc->inpa) {
    gaim_input_remove(gc->inpa);
    gc->inpa = 0;
  }

  mwGaimPluginData_free(pd);
}


static int mw_prpl_send_im(GaimConnection *gc, const char *name,
			   const char *message, GaimConvImFlags flags) {

  struct mwGaimPluginData *pd;
  struct mwIdBlock who = { (char *) name, NULL };
  struct mwConversation *conv;

  g_return_val_if_fail(gc != NULL, 0);
  pd = gc->proto_data;

  g_return_val_if_fail(pd != NULL, 0);

  conv = mwServiceIm_getConversation(pd->srvc_im, &who);

  if(MW_CONVO_IS_OPEN(conv)) {
    return ! mwConversation_send(conv, mwImSend_PLAIN, message);
  }

  /* queue up the message */
  convo_queue(conv, mwImSend_PLAIN, message);
  
  if(! MW_CONVO_IS_PENDING(conv))
    mwConversation_open(conv);

  return 1;
}


static int mw_prpl_send_typing(GaimConnection *gc, const char *name,
			       int typing) {
  
  struct mwGaimPluginData *pd;
  struct mwIdBlock who = { (char *) name, NULL };
  struct mwConversation *conv;

  gpointer t = GINT_TO_POINTER(!! typing);

  g_return_val_if_fail(gc != NULL, 0);
  pd = gc->proto_data;

  g_return_val_if_fail(pd != NULL, 0);

  conv = mwServiceIm_getConversation(pd->srvc_im, &who);

  if(MW_CONVO_IS_OPEN(conv))
    return ! mwConversation_send(conv, mwImSend_TYPING, t);

  /* don't bother opening a conversation just to send typing
     notification */

  return 1;
}


static void mw_prpl_get_info(GaimConnection *gc, const char *who) {
  ;
}


static void mw_prpl_set_away(GaimConnection *gc, const char *state,
			     const char *message) {

  struct mwSession *session;
  struct mwUserStatus stat;
  const char *m = NULL;

  session = gc_to_session(gc);
  g_return_if_fail(session != NULL);

  mwUserStatus_clone(&stat, mwSession_getUserStatus(session));

  if(state) {
    /* when we go to/from a standard state, the state indicates
       whether we're away or not */

    if(! strcmp(state, GAIM_AWAY_CUSTOM)) {
      /* but when we go to/from a custom state, it's the message which
	 indicates whether we're away or not */

      if(message) {
	stat.status = mwStatus_AWAY;
	m = message;
      } else {
	stat.status = mwStatus_ACTIVE;
      }

    } else if(! strcmp(state, MW_STATE_AWAY)) {
      stat.status = mwStatus_AWAY;
      m = MW_STATE_AWAY;

    } else if(! strcmp(state, MW_STATE_BUSY)) {
      stat.status = mwStatus_BUSY;
      m = MW_STATE_BUSY;

    } else if(! strcmp(state, MW_STATE_ACTIVE)) {
      stat.status = mwStatus_ACTIVE;
    }

  } else {
    stat.status = mwStatus_ACTIVE;
  }

  /* use the optional active message for the account */
  if(stat.status == mwStatus_ACTIVE) {
    GaimAccount *acct;

    acct = gaim_connection_get_account(gc);
    m = gaim_account_get_string(acct, MW_KEY_ACTIVE_MSG,
				PLUGIN_DEFAULT_ACTIVE_MSG);
    stat.time = 0;
  }

  /* clean out the old status desc */
  g_free(stat.desc);
  g_free(gc->away);
  stat.desc = NULL;
  gc->away = NULL;

  /* copy in the new status desc if necessary */
  if(m) {
    char *um = gaim_markup_strip_html(m);
    stat.desc = um;
    gc->away = g_strdup(um);
  }

  mwSession_setUserStatus(session, &stat);
  mwUserStatus_clear(&stat);
}


static void mw_prpl_set_idle(GaimConnection *gc, int time) {
  struct mwSession *session;
  struct mwUserStatus stat;

  session = gc_to_session(gc);
  g_return_if_fail(session != NULL);

  mwUserStatus_clone(&stat, mwSession_getUserStatus(session));

  if(time > 0 && stat.status == mwStatus_ACTIVE) {
    stat.status = mwStatus_IDLE;

  } else if(time == 0 && stat.status == mwStatus_IDLE) {
    stat.status = mwStatus_ACTIVE;
  }

  mwSession_setUserStatus(session, &stat);
  mwUserStatus_clear(&stat);
}


static gboolean blist_save_cb(gpointer data) {
  struct mwGaimPluginData *pd = data;

  blist_store(pd);
  pd->save_event = 0;
  return FALSE;
}


static void blist_save(struct mwGaimPluginData *pd) {
  if(pd->save_event) return;

  pd->save_event = gaim_timeout_add(BLIST_SAVE_SECONDS * 1000,
				    blist_save_cb, pd);
}


static void list_on_aware(struct mwAwareList *list,
			  struct mwAwareSnapshot *aware,
			  gpointer data) {

  GaimConnection *gc = data;
  time_t idle = 0;
  guint type = aware->status.status;

  switch(type) {
  case mwStatus_IDLE:
    idle = -1;
    break;

  case mwStatus_AWAY:
  case mwStatus_BUSY:
    type |= UC_UNAVAILABLE;
    break;
  }

  serv_got_update(gc, aware->id.user, aware->online, 0, 0, idle, type);
}


static struct mwAwareList *
ensure_list(struct mwGaimPluginData *pd, GaimGroup *group) {

  struct mwAwareList *list;

  g_return_val_if_fail(pd != NULL, NULL);
  g_return_val_if_fail(group != NULL, NULL);

  list = g_hash_table_lookup(pd->group_map, group);
  if(! list) {
    list = mwAwareList_new(pd->srvc_aware);
    mwAwareList_setOnAware(list, list_on_aware, pd->gc, NULL);
    g_hash_table_replace(pd->group_map, group, list);
  }
  
  return list;
}


static void add_buddy_resolved(struct mwServiceResolve *srvc,
			       guint32 id, guint32 code, GList *results,
			       gpointer buddy) {

  /* if we couldn't find a matching buddy in the resolve service, then
     we remove this buddy */
  if(! code) gaim_blist_remove_buddy(buddy);
}


static void add_buddy(struct mwGaimPluginData *pd,
		      GaimBuddy *buddy, GaimGroup *group) {

  struct mwAwareIdBlock idb = { mwAware_USER, (char *) buddy->name, NULL };
  struct mwAwareList *list;

  GList *add = g_list_prepend(NULL, &idb);

  group = gaim_find_buddys_group(buddy);
  list = ensure_list(pd, group);

  if(mwAwareList_addAware(list, add)) {
    blist_save(pd);
  } else {
    gaim_blist_remove_buddy(buddy);
  }

  g_list_free(add);  
}


static void mw_prpl_add_buddy(GaimConnection *gc,
			      GaimBuddy *buddy, GaimGroup *group) {

  struct mwGaimPluginData *pd;
  struct mwServiceResolve *srvc;
  GList *query;
  enum mwResolveFlag flags;
  guint32 req;

  pd = gc->proto_data;
  srvc = pd->srvc_resolve;

  query = g_list_prepend(NULL, buddy->name);
  flags = mwResolveFlag_FIRST | mwResolveFlag_USERS;

  req = mwServiceResolve_resolve(srvc, query, flags, add_buddy_resolved,
				 buddy, NULL);

  if(req == SEARCH_ERROR) {
    gaim_blist_remove_buddy(buddy);
  } else {
    add_buddy(pd, buddy, group);
  }
}


static void mw_prpl_remove_buddy(GaimConnection *gc,
				 GaimBuddy *buddy, GaimGroup *group) {

  struct mwGaimPluginData *pd;
  struct mwAwareIdBlock idb = { mwAware_USER, buddy->name, NULL };
  struct mwAwareList *list;

  GList *rem = g_list_prepend(NULL, &idb);

  pd = gc->proto_data;
  group = gaim_find_buddys_group(buddy);
  list = ensure_list(pd, group);

  mwAwareList_removeAware(list, rem);
  blist_save(pd);

  g_list_free(rem);
}


static void mw_prpl_add_permit(GaimConnection *gc, const char *name) {
  ;
}


static void mw_prpl_add_deny(GaimConnection *gc, const char *name) {
  ;
}


static void mw_prpl_rem_permit(GaimConnection *gc, const char *name) {
  ;
}


static void mw_prpl_rem_deny(GaimConnection *gc, const char *name) {
  ;
}


static void mw_prpl_set_permit_deny(GaimConnection *gc) {
  ;
}


static struct mwConference *conf_find(struct mwServiceConference *srvc,
				      const char *name) {
  GList *l, *ll;
  struct mwConference *conf = NULL;

  ll = mwServiceConference_getConferences(srvc);
  for(l = ll; l; l = l->next) {
    struct mwConference *c = l->data;
    if(! strcmp(name, mwConference_getName(c))) {
      conf = c;
      break;
    }
  }
  g_list_free(ll);

  return conf;
}


static void mw_prpl_join_chat(GaimConnection *gc,
			      GHashTable *components) {

  struct mwGaimPluginData *pd;
  struct mwServiceConference *srvc;
  struct mwConference *conf;
  char *c;

  pd = gc->proto_data;
  srvc = pd->srvc_conf;

  c = g_hash_table_lookup(components, CHAT_KEY_NAME);

  if(c) {
    DEBUG_INFO("accepting conference invitation\n");
    conf = conf_find(srvc, c);
    if(conf) mwConference_accept(conf);

  } else {
    DEBUG_INFO("creating new conference\n");
    c = g_hash_table_lookup(components, CHAT_KEY_TOPIC);
    conf = mwConference_new(srvc, c);
    mwConference_open(conf);
  }
}


static void mw_prpl_reject_chat(GaimConnection *gc,
				GHashTable *components) {

  struct mwGaimPluginData *pd;
  struct mwServiceConference *srvc;
  char *c;
  
  pd = gc->proto_data;
  srvc = pd->srvc_conf;

  c = g_hash_table_lookup(components, CHAT_KEY_NAME);
  if(c) {
    struct mwConference *conf = conf_find(srvc, c);
    if(conf) mwConference_reject(conf, ERR_SUCCESS, "Declined");
  }
}


static char *mw_prpl_get_chat_name(GHashTable *components) {
  return g_hash_table_lookup(components, CHAT_KEY_NAME);
}


static void mw_prpl_chat_invite(GaimConnection *gc, int id,
				const char *who, const char *invitation) {

  struct mwGaimPluginData *pd;
  struct mwConference *conf;
  struct mwIdBlock idb = { (char *) who, NULL };

  pd = gc->proto_data;

  g_return_if_fail(pd != NULL);
  conf = ID_TO_CONF(pd, id);

  g_return_if_fail(conf != NULL);
  
  mwConference_invite(conf, &idb, invitation);
}


static void mw_prpl_chat_leave(GaimConnection *gc, int id) {
  struct mwGaimPluginData *pd;
  struct mwConference *conf;

  pd = gc->proto_data;

  g_return_if_fail(pd != NULL);
  conf = ID_TO_CONF(pd, id);

  g_return_if_fail(conf != NULL);
  
  mwConference_destroy(conf, ERR_SUCCESS, "Leaving");
}


static void mw_prpl_chat_whisper(GaimConnection *gc, int id,
				 const char *who, const char *message) {
  /* @todo send an IM */
}


static int mw_prpl_chat_send(GaimConnection *gc, int id,
			      const char *message) {

  struct mwGaimPluginData *pd;
  struct mwConference *conf;

  pd = gc->proto_data;

  g_return_val_if_fail(pd != NULL, 0);
  conf = ID_TO_CONF(pd, id);

  g_return_val_if_fail(conf != NULL, 0);
  
  return ! mwConference_sendText(conf, message);
}


static void mw_prpl_keepalive(GaimConnection *gc) {
  struct mwSession *session;

  g_return_if_fail(gc != NULL);

  session = gc_to_session(gc);
  g_return_if_fail(session != NULL);

  mwSession_sendKeepalive(session);
}


static void mw_prpl_alias_buddy(GaimConnection *gc,
				const char *who, const char *alias) {

  struct mwGaimPluginData *pd = gc->proto_data;
  g_return_if_fail(pd != NULL);

  blist_save(pd);
}


static void mw_prpl_buddy_free(GaimBuddy *buddy) {
  ;
}


static void mw_prpl_convo_closed(GaimConnection *gc, const char *who) {
  struct mwGaimPluginData *pd = gc->proto_data;
  struct mwServiceIm *srvc;
  struct mwConversation *conv;
  struct mwIdBlock idb = { (char *) who, NULL };

  g_return_if_fail(pd != NULL);

  srvc = pd->srvc_im;
  g_return_if_fail(srvc != NULL);

  conv = mwServiceIm_findConversation(srvc, &idb);
  if(! conv) return;

  if(MW_CONVO_IS_OPEN(conv))
    mwConversation_close(conv, ERR_SUCCESS);
}


static const char *mw_prpl_normalize(const GaimAccount *account,
				     const char *id) {

  /* code elsewhere assumes that the return value points to different
     memory than the passed value, but it won't free the normalized
     data */

  static char buf[BUF_LEN];
  strncpy(buf, id, sizeof(buf));  
  return buf;
}


static gboolean mw_prpl_can_receive_file(GaimConnection *gc,
					 const char *who) {
  return FALSE;
}


static void mw_prpl_send_file(GaimConnection *gc,
			      const char *who, const char *file) {
  ;
}


static GaimPluginProtocolInfo mw_prpl_info = {
  .options                   = 0,
  .user_splits               = NULL,
  .protocol_options          = NULL,
  .icon_spec                 = NO_BUDDY_ICONS,
  .list_icon                 = mw_prpl_list_icon,
  .list_emblems              = mw_prpl_list_emblems,
  .status_text               = mw_prpl_status_text,
  .tooltip_text              = mw_prpl_tooltip_text,
  .away_states               = mw_prpl_away_states,
  .blist_node_menu           = mw_prpl_blist_node_menu,
  .chat_info                 = mw_prpl_chat_info,
  .chat_info_defaults        = mw_prpl_chat_info_defaults,
  .login                     = mw_prpl_login,
  .close                     = mw_prpl_close,
  .send_im                   = mw_prpl_send_im,
  .set_info                  = NULL,
  .send_typing               = mw_prpl_send_typing,
  .get_info                  = mw_prpl_get_info,
  .set_away                  = mw_prpl_set_away,
  .set_idle                  = mw_prpl_set_idle,
  .change_passwd             = NULL,
  .add_buddy                 = mw_prpl_add_buddy,
  .add_buddies               = NULL,
  .remove_buddy              = mw_prpl_remove_buddy,
  .remove_buddies            = NULL,
  .add_permit                = mw_prpl_add_permit,
  .add_deny                  = mw_prpl_add_deny,
  .rem_permit                = mw_prpl_rem_permit,
  .rem_deny                  = mw_prpl_rem_deny,
  .set_permit_deny           = mw_prpl_set_permit_deny,
  .warn                      = NULL,
  .join_chat                 = mw_prpl_join_chat,
  .reject_chat               = mw_prpl_reject_chat,
  .get_chat_name             = mw_prpl_get_chat_name,
  .chat_invite               = mw_prpl_chat_invite,
  .chat_leave                = mw_prpl_chat_leave,
  .chat_whisper              = mw_prpl_chat_whisper,
  .chat_send                 = mw_prpl_chat_send,
  .keepalive                 = mw_prpl_keepalive,
  .register_user             = NULL,
  .get_cb_info               = NULL,
  .get_cb_away               = NULL,
  .alias_buddy               = mw_prpl_alias_buddy,
  .group_buddy               = NULL,
  .rename_group              = NULL,
  .buddy_free                = mw_prpl_buddy_free,
  .convo_closed              = mw_prpl_convo_closed,
  .normalize                 = mw_prpl_normalize,
  .set_buddy_icon            = NULL,
  .remove_group              = NULL,
  .get_cb_real_name          = NULL,
  .set_chat_topic            = NULL,
  .find_blist_chat           = NULL,
  .roomlist_get_list         = NULL,
  .roomlist_expand_category  = NULL,
  .can_receive_file          = mw_prpl_can_receive_file,
  .send_file                 = mw_prpl_send_file,
};


static GaimPluginPrefFrame *
mw_plugin_get_plugin_pref_frame(GaimPlugin *plugin) {
  GaimPluginPrefFrame *frame;
  GaimPluginPref *pref;
  
  frame = gaim_plugin_pref_frame_new();
  
  pref = gaim_plugin_pref_new_with_label("Remotely Stored Buddy List");
  gaim_plugin_pref_frame_add(frame, pref);
  

  pref = gaim_plugin_pref_new_with_name(MW_PRPL_OPT_BLIST_ACTION);
  gaim_plugin_pref_set_label(pref, "Buddy List Storage Options");

  gaim_plugin_pref_set_type(pref, GAIM_PLUGIN_PREF_CHOICE);
  gaim_plugin_pref_add_choice(pref, "Local Buddy List Only",
			      GINT_TO_POINTER(BLIST_CHOICE_NONE));
  gaim_plugin_pref_add_choice(pref, "Load List from Server",
			      GINT_TO_POINTER(BLIST_CHOICE_LOAD));
  gaim_plugin_pref_add_choice(pref, "Load and Save List to Server",
			      GINT_TO_POINTER(BLIST_CHOICE_SAVE));

  gaim_plugin_pref_frame_add(frame, pref);

  pref = gaim_plugin_pref_new();
  gaim_plugin_pref_set_type(pref, GAIM_PLUGIN_PREF_INFO);
  gaim_plugin_pref_set_label(pref, BLIST_WARNING);
  gaim_plugin_pref_frame_add(frame, pref);

  return frame;
}


static GaimPluginUiInfo mw_plugin_ui_info = {
  .get_plugin_pref_frame = mw_plugin_get_plugin_pref_frame,
};


static gboolean mw_plugin_load(GaimPlugin *plugin) {
  return TRUE;
}


static gboolean mw_plugin_unload(GaimPlugin *plugin) {
  return TRUE;
}


static void mw_plugin_destroy(GaimPlugin *plugin) {
  ;
}


static void active_msg_action_cb(GaimConnection *gc, char *msg) {
  GaimAccount *acct;

  acct = gaim_connection_get_account(gc);
  gaim_account_set_string(acct, MW_KEY_ACTIVE_MSG, msg);

  if(!gc->away_state || !strcmp(gc->away_state, MW_STATE_ACTIVE))
    serv_set_away(gc, MW_STATE_ACTIVE, NULL);
}


static void active_msg_action(GaimPluginAction *act) {
  GaimConnection *gc;
  GaimAccount *account;
  const char *desc;

  gc = act->context;
  account = gaim_connection_get_account(gc);
  desc = gaim_account_get_string(account, MW_KEY_ACTIVE_MSG,
				 PLUGIN_DEFAULT_ACTIVE_MSG);
  
  gaim_request_input(gc, NULL, "Active Message:", NULL,
		     desc,
		     TRUE, FALSE, NULL,
		     _("OK"), G_CALLBACK(active_msg_action_cb),
		     _("Cancel"), NULL,
		     gc);
}


static GList *mw_plugin_actions(GaimPlugin *plugin, gpointer context) {
  GaimPluginAction *act;
  GList *l = NULL;

  act = gaim_plugin_action_new("Set Active Message...", active_msg_action);
  l = g_list_append(l, act);

  return l;
}


static GaimPluginInfo mw_plugin_info = {
  .magic            = GAIM_PLUGIN_MAGIC,
  .major_version    = GAIM_MAJOR_VERSION,
  .minor_version    = GAIM_MINOR_VERSION,
  .type             = GAIM_PLUGIN_PROTOCOL,
  .ui_requirement   = NULL,
  .flags            = 0,
  .dependencies     = NULL,
  .priority         = GAIM_PRIORITY_DEFAULT,
  .id               = PLUGIN_ID,
  .name             = PLUGIN_NAME,
  .version          = VERSION,
  .summary          = PLUGIN_SUMMARY,
  .description      = PLUGIN_DESC,
  .author           = PLUGIN_AUTHOR,
  .homepage         = PLUGIN_HOMEPAGE,
  .load             = mw_plugin_load,
  .unload           = mw_plugin_unload,
  .destroy          = mw_plugin_destroy,
  .ui_info          = NULL,
  .extra_info       = &mw_prpl_info,
  .prefs_info       = &mw_plugin_ui_info,
  .actions          = mw_plugin_actions,
};


static void mw_log_handler(const gchar *d, GLogLevelFlags flags,
			   const gchar *m, gpointer data) {
#if defined(DEBUG)
  char *nl;

  if(! m) return;

  nl = g_strconcat(m, "\n", NULL);

  /* handle g_log requests via gaim's built-in debug logging */
  if(flags & G_LOG_LEVEL_ERROR) {
    gaim_debug_error(d, nl);

  } else if(flags & G_LOG_LEVEL_WARNING) {
    gaim_debug_warning(d, nl);

  } else {
    gaim_debug_info(d, nl);
  }

  g_free(nl);
  
#else
  ; /* nothing at all */
#endif
}


static void mw_plugin_init(GaimPlugin *plugin) {
  GaimAccountUserSplit *split;
  GaimAccountOption *opt;
  GList *l = NULL;

  /* set up account ID as user:server */
  split = gaim_account_user_split_new(_("Server"), PLUGIN_DEFAULT_HOST, ':');
  l = g_list_append(l, split);
  mw_prpl_info.user_splits = l;
  l = NULL;

  /* hide the port in options though, since it's very rare to change */
  opt = gaim_account_option_int_new("Port", MW_KEY_PORT, PLUGIN_DEFAULT_PORT);
  l = g_list_append(l, opt);
  mw_prpl_info.protocol_options = l;
  l = NULL;

  /* set up the prefs for blist options */
  gaim_prefs_add_none(MW_PRPL_OPT_BASE);
  gaim_prefs_add_int(MW_PRPL_OPT_BLIST_ACTION, BLIST_CHOICE_NONE);

  /* use gaim's debug logging */
  g_log_set_handler(G_LOG_DOMAIN,
		    G_LOG_LEVEL_MASK | G_LOG_FLAG_FATAL | G_LOG_FLAG_RECURSION,
		    mw_log_handler, NULL);

  g_log_set_handler("meanwhile",
		    G_LOG_LEVEL_MASK | G_LOG_FLAG_FATAL | G_LOG_FLAG_RECURSION,
		    mw_log_handler, NULL);
}


GAIM_INIT_PLUGIN(meanwhile, mw_plugin_init, mw_plugin_info);
/* The End. */

