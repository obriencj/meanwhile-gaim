
/* Meanwhile Gaim Protocol Plugin (prpl). Adds Lotus Sametime support
to Gaim.

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
USA. */


#define GAIM_PLUGINS
#include <gaim.h>
#include <accountopt.h>
#include <conversation.h>
#include <debug.h>
#include <internal.h>
#include <notify.h>
#include <plugin.h>
#include <prpl.h>
#include <util.h>
#include <version.h>

#include <glib.h>
#include <glib/ghash.h>
#include <glib/glist.h>

#include <meanwhile.h>
#include <st_list.h>
#include <srvc_aware.h>
#include <srvc_conf.h>
#include <srvc_im.h>
#include <srvc_store.h>


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
#define MW_CONNECT_STEPS  7
#define MW_CONNECT_1  _("Looking up server")
#define MW_CONNECT_2  _("Sending Handshake")
#define MW_CONNECT_3  _("Waiting for Handshake Acknowledgement")
#define MW_CONNECT_4  _("Handshake Acknowledged, Sending Login")
#define MW_CONNECT_5  _("Waiting for Login Acknowledgement")
#define MW_CONNECT_6  _("Login Acknowledged")


/* stages of conciousness */
#define UC_NORMAL  0x10
#define MW_STATE_OFFLINE  _("Offline")
#define MW_STATE_ACTIVE   _("Active")
#define MW_STATE_AWAY     _("Away")
#define MW_STATE_BUSY     _("Do Not Disturb")
#define MW_STATE_IDLE     _("Idle")
#define MW_STATE_UNKNOWN  _("Unknown")
#define MW_STATE_ENLIGHTENED  _("Buddha")


/* keys to get/set chat information */
#define CHAT_CREATOR_KEY  "chat_creator"
#define CHAT_NAME_KEY     "chat_name"
#define CHAT_TOPIC_KEY    "chat_topic"
#define CHAT_INVITE_KEY   "chat_invite"


/* keys to get/set gaim plugin information */
#define MW_KEY_HOST       "server"
#define MW_KEY_PORT       "port"


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


/** default inactivity threshold for the gaim plugin to pass to
    mwChannel_destroyInactive. length in seconds */
#define INACTIVE_THRESHOLD  30


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


#define DEBUG_ERROR(a...)  gaim_debug_error(G_LOG_DOMAIN, a)
#define DEBUG_INFO(a...)   gaim_debug_info(G_LOG_DOMAIN, a)
#define DEBUG_MISC(a...)   gaim_debug_misc(G_LOG_DOMAIN, a)
#define DEBUG_WARN(a...)   gaim_debug_warning(G_LOG_DOMAIN, a)


/** get the mw_handler from a mwSession */
#define SESSION_HANDLER(session) \
  ((struct mw_handler *) (session)->handler)


/** get the mw_plugin_data from a GaimConnection */
#define PLUGIN_DATA(gc) \
  ((struct mw_plugin_data *) (gc)->proto_data)


/** get the mwSession from a GaimConnection */
#define GC_TO_SESSION(gc) \
  ((PLUGIN_DATA(gc))->session)


/** get the GaimConnection from a mwSession */
#define SESSION_TO_GC(session) \
  ((SESSION_HANDLER(session))->gc)


struct mw_plugin_data {
  struct mwSession *session;

  struct mwServiceAware *srvc_aware;

  struct mwServiceConf *srvc_conf;

  struct mwServiceIM *srvc_im;

  struct mwServiceStorage *srvc_store;

  GHashTable *list_map;
  GHashTable *convo_map;

  guint save_event;  /**< event id for the save callback */
};


struct mw_handler {
  struct mwSessionHandler super;
  int sock_fd;
  GaimConnection *gc;
};


/** returns 0 if all bytes were written successfully, -1 for any sort
    of failure. */
static int mw_handler_write(struct mwSessionHandler *this,
			    const char *b, gsize n) {

  struct mw_handler *h = (struct mw_handler *) this;
  int ret = 0;

  if(! h->sock_fd)
    return 0;

  while(n) {
    ret = write(h->sock_fd, b, n);
    if(ret <= 0) break;
    n -= ret;
  }

  if(n > 0) {
    /* if there's data left over, something must have failed */
    DEBUG_ERROR("mw_handler_write returning %i\n", ret);
    gaim_connection_error(h->gc, "Connection died");
    mw_handler_close(this);
    return -1;

  } else {
    return 0;
  }
}


static void mw_handler_close(struct mwSessionHandler *this) {
  struct mw_handler *h = (struct mw_handler *) this;
  close(h->sock_fd);
  h->sock_fd = 0;
}


static void mw_handler_init(struct mw_handler *h, int sock_fd,
			    GaimConnection *gc) {

  h->super.write = mw_handler_write;
  h->super.close = mw_handler_close;

  h->sock_fd = sock_fd;
  h->gc = gc;
}


static void mw_read_callback(gpointer data, gint source,
			     GaimInputCondition cond) {

  GaimConnection *gc = (GaimConnection *) data;
  struct mwSession *session = GC_TO_SESSION(gc);
  struct mw_handler *h = SESSION_HANDLER(session);
  
  if(cond & GAIM_INPUT_READ) {
    char buf[READ_BUFFER_SIZE];
    int len = READ_BUFFER_SIZE;

    /* note, don't use gsize. len might become -1 */

    len = read(h->sock_fd, buf, len);
    if(len > 0) {
      DEBUG_INFO("read %i bytes\n", len);
      mwSession_recv(session, buf, (gsize) len);
      return;
    }
  }

  /* fall-through indicates an error */
  gaim_connection_destroy(gc);
}


static void mw_login_callback(gpointer data, gint source,
			      GaimInputCondition cond) {

  GaimConnection *gc = (GaimConnection *) data;
  struct mwSession *session = GC_TO_SESSION(gc);
  struct mw_handler *h;

  if(! g_list_find(gaim_connections_get_all(), data)) {
    close(source);
    g_return_if_reached();
  }

  if(source < 0) {
    gaim_connection_error(gc, "Unable to connect");
    DEBUG_ERROR(" unable to connect in mw_login_callback\n");
    return;
  }

  h = g_new0(struct mw_handler, 1);
  mw_handler_init(h, source, gc);
  session->handler = (struct mwSessionHandler *) h;

  gc->inpa = gaim_input_add(source, GAIM_INPUT_READ, mw_read_callback, gc);
  mwSession_start(session);
}


static void mw_keepalive(GaimConnection *gc) {
  struct mwSession *s = GC_TO_SESSION(gc);
  char c = 0x80;

  g_return_if_fail(s);

  if(mw_handler_write(s->handler, &c, 1)) {
    DEBUG_WARN("sending keepalive byte failed\n");

  } else {
    /* close any OPEN or WAIT channels which have been inactive for at
       least the INACTIVE_THRESHOLD seconds, but only if we're still
       connected. */
    mwChannelSet_destroyInactive(s->channels,
				 time(NULL) - INACTIVE_THRESHOLD);
  }
}


static void on_initConnect(struct mwSession *s) {
  GaimConnection *gc = SESSION_TO_GC(s);

  gaim_connection_update_progress(gc, MW_CONNECT_2, 2, MW_CONNECT_STEPS);
  onStart_sendHandshake(s);
}


static void on_handshake(struct mwSession *s, struct mwMsgHandshake *msg) {
  GaimConnection *gc = SESSION_TO_GC(s);

  gaim_connection_update_progress(gc, MW_CONNECT_3, 3, MW_CONNECT_STEPS);
}


static void on_handshakeAck(struct mwSession *s,
			    struct mwMsgHandshakeAck *msg) {

  GaimConnection *gc = SESSION_TO_GC(s);

  gaim_connection_update_progress(gc, MW_CONNECT_4, 4, MW_CONNECT_STEPS);
  onHandshakeAck_sendLogin(s, msg);
}


static void on_login(struct mwSession *s, struct mwMsgLogin *msg) {
  GaimConnection *gc = SESSION_TO_GC(s);

  gaim_connection_update_progress(gc, MW_CONNECT_5, 5, MW_CONNECT_STEPS);
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
  const char *name = mwSametimeUser_getName(stuser);
  const char *alias = mwSametimeUser_getAlias(stuser);

  buddy = gaim_find_buddy_in_group(acct, id, group);
  if(! buddy) {
    buddy = gaim_buddy_new(acct, id, alias);
    buddy->server_alias = g_strdup(name);
    gaim_blist_add_buddy(buddy, NULL, group, NULL);

    /* why doesn't the above trigger this? need to let meanwhile know
       about these buddies. */
    serv_add_buddy(gc, buddy);
  }

  return buddy;
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
    stg = mwSametimeGroup_new(stlist, grp->name);

    for(cn = gn->child; cn; cn = cn->next) {
      if(! GAIM_BLIST_NODE_IS_CONTACT(cn)) continue;

      for(bn = cn->child; bn; bn = bn->next) {
	if(! GAIM_BLIST_NODE_IS_BUDDY(bn)) continue;
	bdy = (GaimBuddy *) bn;

	if(bdy->account == acct) {
	  idb.user = bdy->name;
	  mwSametimeUser_new(stg, &idb, bdy->server_alias, bdy->alias);
	}	
      }
    }
  }  
}


static void save_blist(GaimConnection *gc) {
  /* - export blist
     - serialize blist to buffer
     - free blist
     - store buffer as string
     - free buffer */

  struct mwSametimeList *stlist;

  struct mwServiceStorage *storage;
  struct mwStorageUnit *unit;

  char *b, *buf;
  gsize n, len;

  struct mw_plugin_data *pd = PLUGIN_DATA(gc);
  g_return_if_fail(pd != NULL);

  storage = pd->srvc_store;
  g_return_if_fail(storage != NULL);

  /* check if we should do this, according to user prefs */
  if(! BLIST_CHOICE_IS_SAVE()) {
    DEBUG_INFO("preferences indicate not to save remote blist\n");
    return;
  }

  if(MW_SERVICE_IS_DEAD(storage)) {
    DEBUG_INFO("aborting save of blist: storage service is not alive\n");
    return;
  }

  stlist = mwSametimeList_new();
  export_blist(gc, stlist);

  n = len = mwSametimeList_buflen(stlist);
  b = buf = (char *) g_malloc0(len);

  if(mwSametimeList_put(&b, &n, stlist)) {
    g_free(buf);
    mwSametimeList_free(stlist);
    DEBUG_WARN("export blist failed while serializing\n");
    return;
  }

  mwSametimeList_free(stlist);

  unit = mwStorageUnit_newString(mwStore_AWARE_LIST, buf);
  /* g_message("----- begin export blist -----\n"
	    "%s\n"
	    "------ end export blist ------", buf); */
  g_free(buf);

  mwServiceStorage_save(storage, unit, NULL, NULL);
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


static void storage_load_cb(struct mwServiceStorage *srvc, guint result,
			    struct mwStorageUnit *item, gpointer dat) {

  struct mwSametimeList *stlist;
  struct mwSession *s;
  char *b, *tmp;
  gsize n;

  if(result) return;

  b = tmp = mwStorageUnit_asString(item);
  if(b == NULL) return;

  n = strlen(b);
  if(! n) return;

  stlist = mwSametimeList_new();
  mwSametimeList_get(&b, &n, stlist);

  s = mwService_getSession(MW_SERVICE(srvc));
  import_blist(SESSION_TO_GC(s), stlist);

  mwSametimeList_free(stlist);

  g_free(tmp);
}


static void fetch_blist(struct mwServiceStorage *srvc) {
  struct mwStorageUnit *unit = mwStorageUnit_new(mwStore_AWARE_LIST);
  mwServiceStorage_load(srvc, unit, storage_load_cb, NULL);
}


static void on_loginAck(struct mwSession *s, struct mwMsgLoginAck *msg) {
  GaimConnection *gc = SESSION_TO_GC(s);
  struct mw_plugin_data *pd = (struct mw_plugin_data *) gc->proto_data;

  gaim_connection_update_progress(gc, MW_CONNECT_6, 6, MW_CONNECT_STEPS);
  gaim_connection_set_state(gc, GAIM_CONNECTED);
  serv_finish_login(gc);

  /* later this won't be necessary, as the session will auto-start
     services on receipt of the service available message */

  mwService_start(MW_SERVICE(pd->srvc_conf));
  mwService_start(MW_SERVICE(pd->srvc_im));
  mwService_start(MW_SERVICE(pd->srvc_store));

  /* timing needs this to happen last */
  mwService_start(MW_SERVICE(pd->srvc_aware));

  fetch_blist(pd->srvc_store);
}


static void on_closeConnect(struct mwSession *session, guint32 reason) {
  GaimConnection *gc;

  if(SESSION_HANDLER(session) == NULL) return;

  gc = SESSION_TO_GC(session);
  g_return_if_fail(gc != NULL);

  if(reason & ERR_FAILURE) {
    gchar *text = mwError(reason);
    gaim_connection_error(gc, text);
    g_free(text);

#if 0
  } else if(gc->inpa) {
    /* therefore disconnect is not an error */
    /* remove the input checker, so that closing the socket won't be
       seen as an error, and won't trigger a re-connect */
    gaim_input_remove(gc->inpa);
    gc->inpa = 0;
#endif
  }
}


static void on_setUserStatus(struct mwSession *s,
			     struct mwMsgSetUserStatus *msg) {

  /* this plugin allows the user to add themselves to their buddy
     list. the server's aware service doesn't always honor that by
     sending updates back to us. so we're going to ensure our status
     is updated by passing it back to the aware service when we
     receive a SetUserStatus message */

  GaimConnection *gc = SESSION_TO_GC(s);
  struct mw_plugin_data *pd = PLUGIN_DATA(gc);
  struct mwServiceAware *srvc = pd->srvc_aware;

  struct mwAwareIdBlock id = { mwAware_USER,
			       s->login.user_id,
			       s->login.community };

  mwServiceAware_setStatus(srvc, &id, &msg->status);
}


static void on_admin(struct mwSession *s, struct mwMsgAdmin *msg) {
  gaim_notify_message(SESSION_TO_GC(s), GAIM_NOTIFY_MSG_INFO,
		      _("Admin Alert"), msg->text, NULL, NULL, NULL);
}


static void got_error(struct mwServiceIM *srvc,
		      struct mwIdBlock *who, unsigned int err) {

  GaimConversation *conv = gaim_find_conversation(who->user);
  char *text, *tmp;

  g_return_if_fail(conv);

  tmp = mwError(err);
  text = g_strconcat("Unable to send message: ", tmp, NULL);

  gaim_conversation_write(conv, who->user, text,
			  GAIM_MESSAGE_SYSTEM,time(NULL));
  g_free(tmp);
  g_free(text);
}


static void got_text(struct mwServiceIM *srvc,
		     struct mwIdBlock *who, const char *text) {

  /* if user@community split, compose buddy name */

  struct mwSession *s = srvc->service.session;
  char *esc = gaim_escape_html(text);
  serv_got_im(SESSION_TO_GC(s), who->user, esc, 0, time(NULL));
  g_free(esc);
}


static void got_typing(struct mwServiceIM *srvc,
		       struct mwIdBlock *who, gboolean typing) {

  /* if user@community split, compose buddy name */

  struct mwSession *s = srvc->service.session;

  if(typing) {
    serv_got_typing(SESSION_TO_GC(s), who->user, 0, GAIM_TYPING);
  } else {
    serv_got_typing_stopped(SESSION_TO_GC(s), who->user);
  }
}


static void got_aware(struct mwAwareList *list,
		      struct mwSnapshotAwareIdBlock *idb, gpointer data) {

  GaimConnection *gc = (GaimConnection *) data;
  time_t idle = 0;

  /* deadbeef or 0 from the client means not idle (unless the status
     indicates otherwise), but deadbeef to the blist causes idle with
     no time */
  /*
  unsigned int i = idb->status.time;

  if( (idb->status.status == mwStatus_IDLE) ||
      ((i > 0) && (i != 0xdeadbeef)) ) {

    idle = (i > 0)? i: 0xdeadbeef;
  }
  */

  /* idle times unused until fixed in a later release */
  if(idb->status.status == mwStatus_IDLE)
    idle = -1;

  serv_got_update(gc, idb->id.user, idb->online,
		  0, 0, idle, idb->status.status);
}


static void got_invite(struct mwConference *conf, struct mwIdBlock *id,
		       const char *text) {

  GaimConnection *gc;
  GHashTable *ht;

  /* the trick here is that we want these strings cleaned up when
     we're done, but not until then. When we return, the originals
     will be cleaned up. The copies are in the hash table, so when the
     hash table goes, they'll be free'd too. Just don't try to free
     the keys */
  char *a, *b, *c, *d;

  gc = SESSION_TO_GC(conf->channel->session);
  ht = g_hash_table_new_full(g_str_hash, g_str_equal, NULL, g_free);

  a = g_strdup(id->user);
  b = g_strdup(conf->name);
  c = g_strdup(conf->topic);
  d = g_strdup(text);

  g_hash_table_insert(ht, CHAT_CREATOR_KEY, a);
  g_hash_table_insert(ht, CHAT_NAME_KEY, b);
  g_hash_table_insert(ht, CHAT_TOPIC_KEY, c);
  g_hash_table_insert(ht, CHAT_INVITE_KEY, d);

  DEBUG_INFO("Got invite: '%s', name: '%s', topic: '%s', text: '%s'\n",
	     a, b, c, d);

  DEBUG_INFO(" triggering serv_got_invite\n");
  serv_got_chat_invite(gc, c, a, d, ht);
}


static void got_welcome(struct mwConference *conf, struct mwIdBlock *members,
			gsize count) {

  GaimConnection *gc = SESSION_TO_GC(conf->channel->session);
  struct mw_plugin_data *pd = PLUGIN_DATA(gc);
  GaimConversation *conv;

  DEBUG_INFO(" got welcome\n");

  conv = serv_got_joined_chat(gc, conf->channel->id, conf->topic);
  gaim_conv_chat_set_id(GAIM_CONV_CHAT(conv), conf->channel->id);

  while(count--) {
    struct mwIdBlock *idb = members + count;
    gaim_conv_chat_add_user(GAIM_CONV_CHAT(conv), idb->user,
			    NULL, GAIM_CBFLAGS_NONE, FALSE);
  }

  /* add a mapping for easier lookup */
  g_hash_table_insert(pd->convo_map, conf, conv);
}


static void got_closed(struct mwConference *conf) {
  GaimConnection *gc = SESSION_TO_GC(conf->channel->session);
  struct mw_plugin_data *pd = PLUGIN_DATA(gc);
  GaimConversation *conv;

  DEBUG_INFO(" got closed\n");

  conv = (GaimConversation *) g_hash_table_lookup(pd->convo_map, conf);

  /* TODO: tell the conv that it's been closed */

  g_hash_table_remove(pd->convo_map, conf);
}


static void got_join(struct mwConference *conf, struct mwIdBlock *id) {
  GaimConnection *gc = SESSION_TO_GC(conf->channel->session);
  struct mw_plugin_data *pd = PLUGIN_DATA(gc);
  GaimConversation *conv;

  conv = (GaimConversation *) g_hash_table_lookup(pd->convo_map, conf);
  if(conv) {
    DEBUG_INFO(" got join\n");
    gaim_conv_chat_add_user(GAIM_CONV_CHAT(conv), id->user,
			    NULL, GAIM_CBFLAGS_NONE, TRUE);
  }
}


static void got_part(struct mwConference *conf, struct mwIdBlock *id) {
  GaimConnection *gc = SESSION_TO_GC(conf->channel->session);
  struct mw_plugin_data *pd = PLUGIN_DATA(gc);
  GaimConversation *conv;

  conv = (GaimConversation *) g_hash_table_lookup(pd->convo_map, conf);
  g_return_if_fail(conv);

  DEBUG_INFO(" got part\n");
  gaim_conv_chat_remove_user(GAIM_CONV_CHAT(conv), id->user, NULL);
}


static void got_conf_text(struct mwConference *conf, struct mwIdBlock *id,
			  const char *text) {

  GaimConnection *gc = SESSION_TO_GC(conf->channel->session);
  struct mw_plugin_data *pd = PLUGIN_DATA(gc);
  GaimConversation *conv;

  conv = (GaimConversation *) g_hash_table_lookup(pd->convo_map, conf);
  g_return_if_fail(conv);

  serv_got_chat_in(gc, gaim_conv_chat_get_id(GAIM_CONV_CHAT(conv)),
		   id->user, 0, text, time(NULL));
}


static void got_conf_typing(struct mwConference *conf, struct mwIdBlock *id,
			    gboolean typing) {

  ; /* no gaim support for this?? oh no! */
}


static void mw_login(GaimAccount *acct) {
  GaimConnection *gc = gaim_account_get_connection(acct);

  struct mw_plugin_data *pd;
  struct mwSession *session;
  struct mwServiceAware *srvc_aware;
  struct mwServiceIM *srvc_im;
  struct mwServiceConf *srvc_conf;
  struct mwServiceStorage *srvc_store;
  
  const char *host;
  unsigned int port;

  gc->proto_data = pd = g_new0(struct mw_plugin_data, 1);

  /* session and call-backs to make everything work */
  pd->session = session = mwSession_new();
  session->on_handshake = on_handshake;
  session->on_handshakeAck = on_handshakeAck;
  session->on_login = on_login;
  session->on_loginAck = on_loginAck;
  session->on_start = on_initConnect;
  session->on_stop = on_closeConnect;
  session->on_setUserStatus = on_setUserStatus;
  session->on_admin = on_admin;

  /* user_id, password */
  session->login.user_id = g_strdup(gaim_account_get_username(acct));
  session->auth.password = g_strdup(gaim_account_get_password(acct));

  /* aware service and call-backs */
  pd->srvc_aware = srvc_aware = mwServiceAware_new(session);
  mwSession_putService(session, MW_SERVICE(srvc_aware));

  /* im service and call-backs */
  pd->srvc_im = srvc_im = mwServiceIM_new(session);
  srvc_im->got_error = got_error;
  srvc_im->got_text = got_text;
  srvc_im->got_typing = got_typing;
  mwSession_putService(session, MW_SERVICE(srvc_im));

  /* conference service and call-backs */
  pd->srvc_conf = srvc_conf = mwServiceConf_new(session);
  srvc_conf->got_invite = got_invite;
  srvc_conf->got_welcome = got_welcome;
  srvc_conf->got_closed = got_closed;
  srvc_conf->got_join = got_join;
  srvc_conf->got_part = got_part;
  srvc_conf->got_text = got_conf_text;
  srvc_conf->got_typing = got_conf_typing;
  mwSession_putService(session, MW_SERVICE(srvc_conf));

  pd->convo_map = g_hash_table_new(NULL, NULL);
  pd->list_map = g_hash_table_new(NULL, NULL);

  /* storage service */
  pd->srvc_store = srvc_store = mwServiceStorage_new(session);
  mwSession_putService(session, MW_SERVICE(srvc_store));

  /* server:port */
  host = gaim_account_get_string(acct, "server", PLUGIN_DEFAULT_HOST);
  port = gaim_account_get_int(acct, "port", PLUGIN_DEFAULT_PORT);

  gaim_connection_update_progress(gc, MW_CONNECT_1, 1, MW_CONNECT_STEPS);

  if(gaim_proxy_connect(acct, host, port, mw_login_callback, gc))
    gaim_connection_error(gc, "Unable to connect");
}


static void mw_close(GaimConnection *gc) {
  struct mwSession *session;
  struct mw_plugin_data *pd = PLUGIN_DATA(gc);

  g_return_if_fail(pd != NULL);

  if(pd->save_event) {
    gaim_timeout_remove(pd->save_event);
    pd->save_event = 0;
  }

  save_blist(gc);

  session = pd->session;
  if(session) {
    mwSession_stop(session, ERR_SUCCESS);

    mwService_free(MW_SERVICE(pd->srvc_aware));
    mwService_free(MW_SERVICE(pd->srvc_conf));
    mwService_free(MW_SERVICE(pd->srvc_im));
    mwService_free(MW_SERVICE(pd->srvc_store));

    g_free(session->handler);
    mwSession_free(session);
  }

  gc->proto_data = NULL;
  g_hash_table_destroy(pd->convo_map);
  g_free(pd);
}


static const char *mw_blist_icon(GaimAccount *a, GaimBuddy *b) {
  /* my little green dude is a chopped up version of the aim running
     guy.  First, cut of the head and store someplace safe. Then, take
     the left-half side of the body and throw it away. Make a copy of
     the remaining body, and flip it horizontally. Now attach the two
     pieces into an X shape, and drop the head back on the top, being
     careful to center it. Then, just change the color saturation to
     bring the red down a bit, and voila! */

  /* then, throw all of that away and use sodipodi to make a new
     icon. You know, LIKE A REAL MAN. */

  /** @todo meanwhile-group icon */

  return "meanwhile";
}


static int mw_im_send(GaimConnection *gc, const char *name,
		      const char *message, GaimConvImFlags flags) {

  struct mw_plugin_data *pd = PLUGIN_DATA(gc);

  /* later support name@community splits */
  struct mwIdBlock t = { (char *) name, NULL };

  return ! mwServiceIM_sendText(pd->srvc_im, &t, message);
}


static void mw_blist_emblems(GaimBuddy *b,
			     char **se, char **sw, char **nw, char **ne) {
  
  unsigned int status = b->uc;

  if(! GAIM_BUDDY_IS_ONLINE(b)) {
    *se = "offline";
  } else if(status == mwStatus_AWAY) {
    *se = "away";
  } else if(status == mwStatus_BUSY) {
    *se = "dnd";
  }
}


static char *mw_status_text(GaimBuddy *b) {
  char *ret = NULL;
  int status = b->uc;

  if(! GAIM_BUDDY_IS_ONLINE(b) ) {
    ret = MW_STATE_OFFLINE;
  } else if( status == mwStatus_AWAY) {
    ret = MW_STATE_AWAY;
  } else if( status == mwStatus_BUSY) {
    ret = MW_STATE_BUSY;
  } else if( status == mwStatus_IDLE) {
    ret = MW_STATE_IDLE;
  } else if( status == mwStatus_ACTIVE) {
    ret = MW_STATE_ACTIVE;
  } else {
    ret = MW_STATE_UNKNOWN;
  }

  return (char *) g_strdup(ret);
}


static char *mw_list_status_text(GaimBuddy *b) {
  GaimConnection *gc = b->account->gc;
  struct mw_plugin_data *pd = PLUGIN_DATA(gc);
  struct mwAwareIdBlock i = { mwAware_USER, b->name, NULL };
  const char *t;

  t = mwServiceAware_getText(pd->srvc_aware, &i);
  return t ? g_strdup(t) : NULL;
}


static char *mw_tooltip_text(GaimBuddy *b) {
  GaimConnection *gc = b->account->gc;
  struct mw_plugin_data *pd = PLUGIN_DATA(gc);

  struct mwAwareIdBlock t = { mwAware_USER, b->name, NULL };

  char *stat, *ret;
  stat = mw_status_text(b);
  ret = (char *) mwServiceAware_getText(pd->srvc_aware, &t);

  if(! ret) {
    ret = g_strconcat("\n<b>Status:</b> ", stat, NULL);

  } else {
    ret = g_strconcat("\n<b>Status:</b> ", stat, "\n"
		      "<b>Message:</b> ", ret, NULL);
  }

  g_free(stat);

  return ret;
}


static GList *mw_away_states(GaimConnection *gc) {
  GList *st = NULL;
  st = g_list_append(st, MW_STATE_ACTIVE);
  st = g_list_append(st, MW_STATE_AWAY);
  st = g_list_append(st, MW_STATE_BUSY);
  st = g_list_append(st, (char *) GAIM_AWAY_CUSTOM);

  return st;
}


static void mw_set_idle(GaimConnection *gc, int t) {
  struct mwSession *s = GC_TO_SESSION(gc);
  struct mwUserStatus stat;

  mwUserStatus_clone(&stat, &s->status);

  /* re-reading the specification, this is incorrect. It should be the
     count of minutes since last action. In order to fix this, I am
     going to turn off all idle-time reporting for the next meanwhile
     version. */

  /* stat.time = (t > 0)? time(NULL) - t: 0; */

  if(t > 0 && stat.status == mwStatus_ACTIVE) {
    /* set active to idle */
    stat.status = mwStatus_IDLE;

  } else if(t == 0 && stat.status == mwStatus_IDLE) {
    /* set idle to active */
    stat.status = mwStatus_ACTIVE;
  }

  mwSession_setUserStatus(s, &stat);
  mwUserStatus_clear(&stat);
}


static int mw_send_typing(GaimConnection *gc, const char *name, int typing) {
  struct mw_plugin_data *pd = PLUGIN_DATA(gc);

  /* later support name@community splits */
  struct mwIdBlock t = { (char *) name, NULL };

  mwServiceIM_sendTyping(pd->srvc_im, &t, !!typing);
  return 0;
}


static void mw_set_away(GaimConnection *gc, const char *state,
			const char *message) {

  struct mwSession *s = GC_TO_SESSION(gc);
  struct mwUserStatus stat;

  const char *m = NULL;

  mwUserStatus_clone(&stat, &s->status);

  if(state != NULL) {
    /* when we go to/from a standard state, the state indicates
       whether we're away or not */

    if(! strcmp(state, GAIM_AWAY_CUSTOM)) {
      /* but when we go to/from a custom state, then it's the message
	 which indicates whether we're away or not */

      if(message != NULL) {
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

    } else {
      stat.status = mwStatus_ACTIVE;
    }

  } else {
    stat.status = mwStatus_ACTIVE;
  }

  /* clean out existing status desc */
  g_free(stat.desc);
  g_free(gc->away);

  /* put in the new status desc if necessary */
  if(m != NULL) {
    char *um = gaim_markup_strip_html(m);
    stat.desc = um;
    gc->away = g_strdup(um);
  } else {
    stat.desc = NULL;
    gc->away = NULL;
  }

  if(stat.status == mwStatus_ACTIVE)
    stat.time = 0;

  mwSession_setUserStatus(s, &stat);
  mwUserStatus_clear(&stat);
}


static void mw_convo_closed(GaimConnection *gc, const char *name) {
  struct mw_plugin_data *pd = PLUGIN_DATA(gc);

  /* later support name@community splits */
  struct mwIdBlock t = { (char *) name, NULL };

  mwServiceIM_closeChat(pd->srvc_im, &t);
}


static struct mwAwareList *ensure_list(GaimConnection *gc, GaimGroup *group) {

  struct mw_plugin_data *pd = PLUGIN_DATA(gc);
  struct mwAwareList *list;

  list = (struct mwAwareList *) g_hash_table_lookup(pd->list_map, group);
  if(! list) {
    list = mwAwareList_new(pd->srvc_aware);
    mwAwareList_setOnAware(list, got_aware, gc);
    g_hash_table_replace(pd->list_map, group, list);
  }
  
  return list;
}


static gboolean cb_stlist_save(gpointer data) {
  GaimConnection *gc = (GaimConnection *) data;
  struct mw_plugin_data *pd = PLUGIN_DATA(gc);

  save_blist(gc);
  pd->save_event = 0x00;
  
  return FALSE;
}


static void schedule_stlist_save(GaimConnection *gc) {
  struct mw_plugin_data *pd = PLUGIN_DATA(gc);

  g_return_if_fail(pd != NULL);

  /* only schedule one save at a time. */
  if(pd->save_event == 0) {
    pd->save_event = gaim_timeout_add(BLIST_SAVE_SECONDS * 1000,
				      cb_stlist_save, gc);
  }
}


static void mw_add_buddy(GaimConnection *gc,
			 GaimBuddy *buddy, GaimGroup *group) {

  struct mwAwareIdBlock t = { mwAware_USER, (char *) buddy->name, NULL };
  struct mwAwareList *list;

  GaimGroup *found = gaim_find_buddys_group(buddy);
  list = ensure_list(gc, found);

  mwAwareList_addAware(list, &t, 1);
  schedule_stlist_save(gc);
}


static void mw_remove_buddy(GaimConnection *gc,
			    GaimBuddy *buddy, GaimGroup *group) {
  
  struct mwAwareIdBlock t = { mwAware_USER, (char *) buddy->name, NULL };
  struct mwAwareList *list = ensure_list(gc, group);

  GaimGroup *found = gaim_find_buddys_group(buddy);
  list = ensure_list(gc, found);

  mwAwareList_removeAware(list, &t, 1);
  schedule_stlist_save(gc);
}


static GList *mw_chat_info(GaimConnection *gc) {
  GList *gl = NULL;
  struct proto_chat_entry *pce;

  pce = g_new0(struct proto_chat_entry, 1);
  pce->label = "Topic:";
  pce->identifier = CHAT_TOPIC_KEY;
  gl = g_list_append(gl, pce);

  return gl;
}


static void mw_chat_join(GaimConnection *gc, GHashTable *components) {
  /* - if KEY_NAME is NULL, it's a new conference
     - create/accept conference as necessary
  */

  struct mwServiceConf *srvc = PLUGIN_DATA(gc)->srvc_conf;
  struct mwConference *conf;
  char *name = g_hash_table_lookup(components, CHAT_NAME_KEY);

  if(name) {
    DEBUG_INFO("accepting conference invite\n");
    conf = mwConference_findByName(srvc, name);
    if(conf) mwConference_accept(conf);

  } else {
    char *topic;
    DEBUG_INFO("creating new conference\n");

    topic = (char *) g_hash_table_lookup(components, CHAT_TOPIC_KEY);
    conf = mwConference_new(srvc);
    conf->topic = g_strdup(topic);
    mwConference_create(conf);
  }
}


static void mw_chat_reject(GaimConnection *gc, GHashTable *components) {
  struct mwServiceConf *srvc = PLUGIN_DATA(gc)->srvc_conf;
  struct mwConference *conf;
  char *name = g_hash_table_lookup(components, CHAT_NAME_KEY);

  if(name) {
    conf = mwConference_findByName(srvc, name);
    if(conf) mwConference_destroy(conf, ERR_SUCCESS, "Declined");
  }
}


static void mw_chat_invite(GaimConnection *gc, int id,
			   const char *message, const char *who) {

  unsigned int uid = (unsigned int) id;
  struct mwServiceConf *srvc = PLUGIN_DATA(gc)->srvc_conf;
  struct mwChannel *chan = mwChannel_find(GC_TO_SESSION(gc)->channels, uid);
  struct mwConference *conf = mwConference_findByChannel(srvc, chan);

  struct mwIdBlock idb = { (char *) who, NULL };

  mwConference_invite(conf, &idb, message);
}


static void mw_chat_leave(GaimConnection *gc, int id) {
  unsigned int uid = (unsigned int) id;
  struct mwServiceConf *srvc = PLUGIN_DATA(gc)->srvc_conf;
  struct mwChannel *chan = mwChannel_find(GC_TO_SESSION(gc)->channels, uid);
  struct mwConference *conf = mwConference_findByChannel(srvc, chan);

  mwConference_destroy(conf, ERR_SUCCESS, "Leaving");
}


static int mw_chat_send(GaimConnection *gc, int id, const char *message) {
  unsigned int uid = (unsigned int) id;
  struct mwServiceConf *srvc = PLUGIN_DATA(gc)->srvc_conf;
  struct mwChannel *chan = mwChannel_find(GC_TO_SESSION(gc)->channels, uid);
  struct mwConference *conf = mwConference_findByChannel(srvc, chan);

  mwConference_sendText(conf, message);
  return 1;
}


static GaimPluginPrefFrame *get_plugin_pref_frame(GaimPlugin *plugin) {
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


static GaimPluginProtocolInfo prpl_info = {
  0,                        /* flags */
  NULL,                     /* user_splits */
  NULL,                     /* protocol options */
  NO_BUDDY_ICONS,           /* buddy icon spec */
  mw_blist_icon,
  mw_blist_emblems,
  mw_list_status_text,
  mw_tooltip_text,
  mw_away_states,
  NULL,                     /* mw_buddy_menu, */
  mw_chat_info,
  NULL,                     /* mw_chat_info_defaults, */
  mw_login,
  mw_close,
  mw_im_send,
  NULL,                     /* get info, */
  mw_send_typing,
  NULL,                     /* set info, */
  mw_set_away,
  mw_set_idle,
  NULL,                     /* change password, */
  mw_add_buddy,
  NULL,                     /* mw_add_buddies, */
  mw_remove_buddy,
  NULL,                     /* mw_remove_buddies, */
  NULL,                     /* mw_add_permit, */
  NULL,                     /* mw_add_deny, */
  NULL,                     /* mw_rem_permit, */
  NULL,                     /* mw_rem_deny, */
  NULL,                     /* mw_set_permit_deny, */
  NULL,                     /* mw_warn */
  mw_chat_join,
  mw_chat_reject,
  NULL,                     /* mw_chat_name, */
  mw_chat_invite,
  mw_chat_leave,
  NULL,                     /* mw_chat_whisper, */
  mw_chat_send,
  mw_keepalive,
  NULL,                     /* register user */
  NULL,                     /* get chat buddy info */
  NULL,                     /* get chat buddy away */
  NULL,                     /* mw_alias_buddy, */
  NULL,                     /* mw_move_buddy, */
  NULL,                     /* mw_rename_group, */
  NULL,                     /* mw_buddy_free, */
  mw_convo_closed,
  NULL,                     /* normalize */
  NULL,                     /* set buddy icon */
  NULL,                     /* remove group */
  NULL,                     /* get chat buddy real name */
  NULL,                     /* set chat topic */
  NULL,                     /* find blist chat */
  NULL,                     /* get room list */
  NULL,                     /* cancel get room list */
  NULL,                     /* expand room list category */
  NULL,                     /* mw_can_receive_file */
  NULL,                     /* mw_send_file */
};


static GaimPluginUiInfo prefs_info = {
  get_plugin_pref_frame
};


static GaimPluginInfo info = {
  GAIM_PLUGIN_MAGIC,
  GAIM_MAJOR_VERSION,
  GAIM_MINOR_VERSION,
  GAIM_PLUGIN_PROTOCOL,     /**< type */
  NULL,                     /**< ui_requirement */
  0,                        /**< flags */
  NULL,                     /**< dependencies */
  GAIM_PRIORITY_DEFAULT,    /**< priority */
  
  PLUGIN_ID,                /**< id */
  PLUGIN_NAME,              /**< name */
  VERSION,                  /**< version */
  PLUGIN_SUMMARY,           /**< summary */
  PLUGIN_DESC,              /**< description */
  PLUGIN_AUTHOR,            /**< author */
  PLUGIN_HOMEPAGE,          /**< homepage */
  
  NULL,                     /**< load */
  NULL,                     /**< unload */
  NULL,                     /**< destroy */
  NULL,                     /**< ui_info */
  &prpl_info,               /**< extra_info */
  &prefs_info,              /**< prefs info */
  NULL                      /**< actions */
};


#ifdef _WIN32
static void dummy_log_handler(const gchar *d, GLogLevelFlags flags,
			      const gchar *m, gpointer data) {
  ; /* nothing at all */
}
#endif


static void init_plugin(GaimPlugin *plugin) {
  GaimAccountOption *opt;

  /* set up the server and port options */
  opt = gaim_account_option_string_new("Server", MW_KEY_HOST,
				       PLUGIN_DEFAULT_HOST);
  prpl_info.protocol_options = g_list_append(prpl_info.protocol_options, opt);

  opt = gaim_account_option_int_new("Port", MW_KEY_PORT, PLUGIN_DEFAULT_PORT);
  prpl_info.protocol_options = g_list_append(prpl_info.protocol_options, opt);

  /* set up the prefs for blist options */
  gaim_prefs_add_none(MW_PRPL_OPT_BASE);
  gaim_prefs_add_int(MW_PRPL_OPT_BLIST_ACTION, BLIST_CHOICE_NONE);

  /* silence plugin and meanwhile library logging for win32 */
  #ifdef _WIN32
  g_log_set_handler(G_LOG_DOMAIN,
		    G_LOG_LEVEL_MASK | G_LOG_FLAG_FATAL | G_LOG_FLAG_RECURSION,
		    dummy_log_handler, NULL);
  g_log_set_handler("meanwhile",
		    G_LOG_LEVEL_MASK | G_LOG_FLAG_FATAL | G_LOG_FLAG_RECURSION,
		    dummy_log_handler, NULL);
  #endif
}


GAIM_INIT_PLUGIN(meanwhile, init_plugin, info)
/* The End. */
