
/*
Meanwhile Gaim Protocol Plugin (prpl). Adds Lotus Sametime support to Gaim.

Copyright (C) 2004 Christopher (siege) O'Brien <obriencj@us.ibm.com>
Copyright (C) 2004 IBM Corporation

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
*/


#define GAIM_PLUGINS
#include <gaim.h>

#include <accountopt.h>
#include <conversation.h>
#include <debug.h>
#include <internal.h>
#include <multi.h>
#include <notify.h>
#include <plugin.h>
#include <prpl.h>

#include <glib.h>
#include <glib/ghash.h>
#include <glib/glist.h>

#include <meanwhile/meanwhile.h>
#include <meanwhile/srvc_aware.h>
#include <meanwhile/srvc_conf.h>
#include <meanwhile/srvc_im.h>

#include "mwgaim.h"


#ifndef os_write
# ifndef _WIN32
#  define os_write(fd, buffer, len) write(fd, buffer, len)
# else
#  define os_write(fd, buffer, len) send(fd, buffer, len, 0)
# endif
#endif


#ifndef os_read
# ifndef _WIN32
#  define os_read(fd, buffer, size) read(fd, buffer, size)
# else
#  define os_read(fd, buffer, size) recv(fd, buffer, size, 0)
# endif
#endif


#ifndef os_close
# ifndef _WIN32
#  define os_close(fd) close(fd)
# else
#  define os_close(fd) closesocket(fd)
# endif
#endif


#define DEBUG_ERROR(a)  gaim_debug_error(G_LOG_DOMAIN, a)
#define DEBUG_INFO(a)   gaim_debug_info(G_LOG_DOMAIN, a)
#define DEBUG_MISC(a)   gaim_debug_misc(G_LOG_DOMAIN, a)
#define DEBUG_WARN(a)   gaim_debug_warning(G_LOG_DOMAIN, a)


#define SESSION_HANDLER(session) \
  ((struct mw_handler *) (session)->handler)


#define PLUGIN_DATA(gc) \
  ((struct mw_plugin_data *) (gc)->proto_data)


#define GC_TO_SESSION(gc) \
  ((PLUGIN_DATA(gc))->session)


#define SESSION_TO_GC(session) \
  ((SESSION_HANDLER(session))->gc)


struct mw_plugin_data {
  struct mwSession *session;
  struct mwServiceIM *srvc_im;
  struct mwServiceAware *srvc_aware;
  struct mwServiceConf *srvc_conf;

  GHashTable *convo_map;
};


struct mw_handler {
  struct mwSessionHandler super;
  int sock_fd;
  GaimConnection *gc;
};


/* returns 0 if all bytes were written successfully, -1 for any sort of
   failure. */
static int mw_handler_write(struct mwSessionHandler *this,
			    const char *b, gsize n) {

  struct mw_handler *h = (struct mw_handler *) this;
  int ret;

  while(n) {
    /* this looks weird, but it's almost sane. I'm going from an unsigned int
       length to a signed int length. The likely-hood of n ever being that
       large is super-duper-minimal, but I don't like chances. So mask off the
       sign bit and only write that many bytes at a time. The normal write
       loop then continues writing until n is decremented to zero, or os_write
       errors */
    ret = os_write(h->sock_fd, b, (n & 0xefffffff));
    if(ret <= 0) break;
    n -= ret;
  }

  if( (ret = n) ) {
    gaim_debug_error(G_LOG_DOMAIN, "mw_handler_write returning %i\n", ret);
    gaim_connection_error(h->gc, "Connection died");
    ret = -1;
  }

  return ret;
}


static void mw_handler_close(struct mwSessionHandler *this) {
  struct mw_handler *h = (struct mw_handler *) this;
  os_close(h->sock_fd);
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

    /* READ_BUFFER_SIZE is defined in mwgaim.h */
    char buf[READ_BUFFER_SIZE];
    gsize len = READ_BUFFER_SIZE;

    len = os_read(h->sock_fd, buf, len);
    if(len > 0) {
      gaim_debug_info(G_LOG_DOMAIN, "read %u bytes", len);
      mwSession_recv(session, buf, (unsigned int) len);
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
    os_close(source);
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
  mwSession_initConnect(session);
}


static void mw_keepalive(GaimConnection *gc) {
  struct mwSession *s = GC_TO_SESSION(gc);
  char c = 0x80;

  g_return_if_fail(s);

  if(mw_handler_write(s->handler, &c, 1)) {
    DEBUG_WARN("looks like keepalive byte failed\n");

  } else {
    /* close any OPEN or WAIT channels which have been inactive for
       at least the INACTIVE_THRESHOLD seconds, but only if we're
       still connected. */
    mwChannelSet_destroyInactive(s->channels, time(NULL) - INACTIVE_THRESHOLD);
  }
}


static void on_initConnect(struct mwSession *s) {
  GaimConnection *gc = SESSION_TO_GC(s);

  gaim_connection_update_progress(gc, MW_CONNECT_2, 2, MW_CONNECT_STEPS);
  initConnect_sendHandshake(s);
}


static void on_handshake(struct mwSession *s, struct mwMsgHandshake *msg) {
  GaimConnection *gc = SESSION_TO_GC(s);

  gaim_connection_update_progress(gc, MW_CONNECT_3, 3, MW_CONNECT_STEPS);
}


static void on_handshakeAck(struct mwSession *s,
			    struct mwMsgHandshakeAck *msg) {

  GaimConnection *gc = SESSION_TO_GC(s);

  gaim_connection_update_progress(gc, MW_CONNECT_4, 4, MW_CONNECT_STEPS);
  handshakeAck_sendLogin(s, msg);
}


static void on_login(struct mwSession *s, struct mwMsgLogin *msg) {
  GaimConnection *gc = SESSION_TO_GC(s);

  gaim_connection_update_progress(gc, MW_CONNECT_5, 5, MW_CONNECT_STEPS);
}


static void on_loginAck(struct mwSession *s, struct mwMsgLoginAck *msg) {
  GaimConnection *gc = SESSION_TO_GC(s);

  gaim_connection_update_progress(gc, MW_CONNECT_6, 6, MW_CONNECT_STEPS);
  gaim_connection_set_state(gc, GAIM_CONNECTED);
  serv_finish_login(gc);
}


static void on_closeConnect(struct mwSession *session, guint32 reason) {
  GaimConnection *gc;

  g_return_if_fail(SESSION_HANDLER(session));

  gc = SESSION_TO_GC(session);
  g_return_if_fail(gc);

  if(reason & ERR_FAILURE) {
    gchar *text = mwError(reason);
    gaim_connection_error(gc, text);
    g_free(text);

  } else if(gc->inpa) {
    /* remove the input checker, so that closing the socket won't be
       seen as an error, and won't trigger a re-connect */
    gaim_input_remove(gc->inpa);
    gc->inpa = 0;
  }
}


static void on_setUserStatus(struct mwSession *s,
			     struct mwMsgSetUserStatus *msg) {

  /* this plugin allows the user to add themselves to their buddy list. the
     server's aware service doesn't always honor that by sending updates back
     to us. so we're going to ensure our status is updated by passing it back
     to the aware service when we receive a SetUserStatus message */

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

  serv_got_im(SESSION_TO_GC(s), who->user, text, 0, time(NULL));
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


static void update_buddy(struct mwSession *s,
			 struct mwSnapshotAwareIdBlock *idb) {

  GaimConnection *gc = SESSION_TO_GC(s);

  time_t idle = 0;
  /* unsigned int i = idb->status.time; */

  /* deadbeef or 0 from the client means not idle (unless the status indicates
     otherwise), but deadbeef to the blist causes idle with no time */
  /*
  if( (idb->status.status == mwStatus_IDLE) ||
      ((i > 0) && (i != 0xdeadbeef)) ) {

    idle = (i > 0)? i: 0xdeadbeef;
  }
  */

  /* over-riding idle times until fixed in a later release */
  if(idb->status.status == mwStatus_IDLE)
    idle = -1;

  serv_got_update(gc, idb->id.user, idb->online,
		  0, 0, idle, idb->status.status);
}


static void got_aware(struct mwServiceAware *srvc,
		      struct mwSnapshotAwareIdBlock *idb, unsigned int c) {

  struct mwSession *s = srvc->service.session;
  while(c--) update_buddy(s, idb + c);
}


static void got_invite(struct mwConference *conf, struct mwIdBlock *id,
		       const char *text) {

  GaimConnection *gc;
  GHashTable *ht;

  /* the trick here is that we want these strings cleaned up when we're done,
     but not until then. When we return, the originals will be cleaned up. The
     copies are in the hash table, so when the hash table goes, they'll be
     free'd too. Just don't try to free the keys */
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

  gaim_debug_info(G_LOG_DOMAIN,
		  "Got invite: '%s', name: '%s', topic: '%s', text: '%s'\n",
		  a, b, c, d);

  DEBUG_INFO(" triggering serv_got_invite\n");
  serv_got_chat_invite(gc, c, a, d, ht);
}


static void got_welcome(struct mwConference *conf, struct mwIdBlock *members,
			unsigned int count) {

  GaimConnection *gc = SESSION_TO_GC(conf->channel->session);
  struct mw_plugin_data *pd = PLUGIN_DATA(gc);
  GaimConversation *conv;

  DEBUG_INFO(" got welcome\n");

  conv = serv_got_joined_chat(gc, conf->channel->id, conf->topic);
  gaim_conv_chat_set_id(GAIM_CONV_CHAT(conv), conf->channel->id);

  while(count--) {
    struct mwIdBlock *idb = members + count;
    gaim_conv_chat_add_user(GAIM_CONV_CHAT(conv), idb->user, NULL);
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
  g_return_if_fail(conv);

  DEBUG_INFO(" got join\n");
  gaim_conv_chat_add_user(GAIM_CONV_CHAT(conv), id->user, NULL);
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

  gaim_debug_info("meanwhile", " got conf text: '%s'\n", text);
  serv_got_chat_in(gc, gaim_conv_chat_get_id(GAIM_CONV_CHAT(conv)),
		   id->user, 0, text, time(NULL));
}


static void got_conf_typing(struct mwConference *conf, struct mwIdBlock *id,
			    gboolean typing) {

  /* no gaim support for this?? oh no! */
}


static void mw_login(GaimAccount *acct) {
  GaimConnection *gc = gaim_account_get_connection(acct);

  struct mw_plugin_data *pd;
  struct mwSession *session;
  struct mwServiceAware *srvc_aware;
  struct mwServiceIM *srvc_im;
  struct mwServiceConf *srvc_conf;
  
  const char *host;
  unsigned int port;

  DEBUG_INFO(" --> mw_login\n");

  gc->proto_data = pd = g_new0(struct mw_plugin_data, 1);

  /* session and call-backs to make everything work */
  pd->session = session = mwSession_new();
  session->on_handshake = on_handshake;
  session->on_handshakeAck = on_handshakeAck;
  session->on_login = on_login;
  session->on_loginAck = on_loginAck;
  session->on_initConnect = on_initConnect;
  session->on_closeConnect = on_closeConnect;
  session->on_setUserStatus = on_setUserStatus;
  session->on_admin = on_admin;

  /* user_id, password */
  session->login.user_id = g_strdup(gaim_account_get_username(acct));
  session->auth.password = g_strdup(gaim_account_get_password(acct));

  /* aware service and call-backs */
  pd->srvc_aware = srvc_aware = mwServiceAware_new(session);
  srvc_aware->got_aware = got_aware;
  mwSession_putService(session, (struct mwService *) srvc_aware);

  /* im service and call-backs */
  pd->srvc_im = srvc_im = mwServiceIM_new(session);
  srvc_im->got_error = got_error;
  srvc_im->got_text = got_text;
  srvc_im->got_typing = got_typing;
  mwSession_putService(session, (struct mwService *) srvc_im);

  /* conference service and call-backs */
  pd->srvc_conf = srvc_conf = mwServiceConf_new(session);
  srvc_conf->got_invite = got_invite;
  srvc_conf->got_welcome = got_welcome;
  srvc_conf->got_closed = got_closed;
  srvc_conf->got_join = got_join;
  srvc_conf->got_part = got_part;
  srvc_conf->got_text = got_conf_text;
  srvc_conf->got_typing = got_conf_typing;
  mwSession_putService(session, (struct mwService *) srvc_conf);

  pd->convo_map = g_hash_table_new(NULL, NULL);

  /* server:port */
  host = gaim_account_get_string(acct, "server", PLUGIN_DEFAULT_HOST);
  port = gaim_account_get_int(acct, "port", PLUGIN_DEFAULT_PORT);

  gaim_connection_update_progress(gc, MW_CONNECT_1, 1, MW_CONNECT_STEPS);

  if(gaim_proxy_connect(acct, host, port, mw_login_callback, gc))
    gaim_connection_error(gc, "Unable to connect");

  DEBUG_INFO(" <-- mw_login\n");  
}


static void mw_close(GaimConnection *gc) {
  struct mwSession *session;
  struct mw_plugin_data *pd = PLUGIN_DATA(gc);

  g_return_if_fail(pd);

  session = GC_TO_SESSION(gc);
  if(session) {
    mwSession_closeConnect(session, ERR_SUCCESS);
    
    /* we created it, so we need to clean it up */
    g_free(session->handler);
    session->handler = NULL;
    mwSession_free(&session);
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
  struct mwIdBlock i = { b->name, NULL};
  const char *t;

  t = mwServiceAware_getText(pd->srvc_aware, &i);
  return t ? g_strdup(t) : NULL;
}


static char *mw_tooltip_text(GaimBuddy *b) {
  GaimConnection *gc = b->account->gc;
  struct mw_plugin_data *pd = PLUGIN_DATA(gc);

  struct mwIdBlock t = { b->name, NULL };

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

  /* re-reading the specification, this is incorrect. It should be the count
     of minutes since last action. In order to fix this, I am going to turn
     off all idle-time reporting for the next meanwhile version. */

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
    /* when we go to/from a standard state, the state indicates whether we're
       away or not */

    if(! strcmp(state, GAIM_AWAY_CUSTOM)) {
      /* but when we go to/from a custom state, then it's the message which
	 indicates whether we're away or not */

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
    stat.desc = g_strdup(m);
    gc->away = g_strdup(m);
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


static void mw_add_buddy(GaimConnection *gc, GaimBuddy *buddy,
			 GaimGroup *group) {

  struct mw_plugin_data *pd = PLUGIN_DATA(gc);

  /* later support name@community splits */
  struct mwIdBlock t = { (char *) buddy->name, NULL };

  mwServiceAware_add(pd->srvc_aware, &t, 1);
}


static void mw_add_buddies(GaimConnection *gc, GList *buddies,
			  GList *groups) {
  GaimBuddy *buddy;
  struct mw_plugin_data *pd = PLUGIN_DATA(gc);
  unsigned int count, c;
  struct mwIdBlock *t;

  count = g_list_length(buddies);
  t = g_new0(struct mwIdBlock, count);

  for(c = count; c--; buddies = buddies->next) {
	buddy = buddies->data;
    (t + c)->user = buddy->name;
  }
  
  mwServiceAware_add(pd->srvc_aware, t, count);
  g_free(t);
}


static void mw_remove_buddy(GaimConnection *gc,
			    GaimBuddy *buddy, GaimGroup *group) {
  
  struct mw_plugin_data *pd = PLUGIN_DATA(gc);

  /* later support name@community splits */
  struct mwIdBlock t = { (char *) buddy->name, NULL };

  mwServiceAware_remove(pd->srvc_aware, &t, 1);
}


static void mw_remove_buddies(GaimConnection *gc, GList *buddies,
			      GList *groups) {
  GaimBuddy *buddy;
  struct mw_plugin_data *pd = PLUGIN_DATA(gc);
  unsigned int count, c;
  struct mwIdBlock *t;

  count = g_list_length(buddies);
  t = g_new0(struct mwIdBlock, count);

  for(c = count; c--; buddies = buddies->next) {
	buddy = buddies->data;
    (t + c)->user = (char *) buddy->name;
  }
  
  mwServiceAware_remove(pd->srvc_aware, t, count);
  g_free(t);
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
    DEBUG_INFO(" accepting conference invite\n");
    conf = mwConference_findByName(srvc, name);
    if(conf) mwConference_accept(conf);

  } else {
    char *topic;
    DEBUG_INFO(" creating new conference\n");

    topic = (char *) g_hash_table_lookup(components, CHAT_TOPIC_KEY);
    conf = mwConference_new(srvc);
    conf->topic = g_strdup(topic);
    mwConference_create(conf);
  }

  DEBUG_INFO(" ... leaving mw_chat_join\n");
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

  DEBUG_INFO(" mw chat leave\n");
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


static GaimPlugin *meanwhile_plugin = NULL;


static GaimPluginProtocolInfo prpl_info = {
  GAIM_PRPL_API_VERSION, /* options */
  0, /* flags? */
  NULL,
  NULL,
  mw_blist_icon,
  mw_blist_emblems,
  mw_list_status_text,
  mw_tooltip_text,
  mw_away_states,
  NULL, /* mw_buddy_menu, */
  mw_chat_info,
  mw_login,
  mw_close,
  mw_im_send,
  NULL, /* mw_set_info, */
  mw_send_typing,
  NULL, /* mw_get_info, */
  mw_set_away,
  mw_set_idle,
  NULL, /* change password, */
  mw_add_buddy,
  mw_add_buddies,
  mw_remove_buddy,
  mw_remove_buddies,
  NULL, /* mw_add_permit, */
  NULL, /* mw_add_deny, */
  NULL, /* mw_rem_permit, */
  NULL, /* mw_rem_deny, */
  NULL, /* mw_set_permit_deny, */
  NULL, /* mw_warn */
  mw_chat_join,
  mw_chat_reject,
  mw_chat_invite,
  mw_chat_leave,
  NULL, /* mw_chat_whisper, */
  mw_chat_send,
  mw_keepalive,
  NULL, /* register user */
  NULL, /* get chat buddy info */
  NULL, /* get chat buddy away */
  NULL, /* mw_alias_buddy, */
  NULL, /* mw_move_buddy, */
  NULL, /* mw_rename_group, */
  NULL, /* mw_buddy_free, */
  mw_convo_closed,
  NULL, /* normalize */
  NULL, /* set buddy icon */
  NULL, /* remove group */
  NULL, /* get chat buddy real name */
  NULL, /* set chat topic */
  NULL, /* find blist chat */
  NULL, /* get room list */
  NULL, /* cancel get room list */
  NULL, /* expand room list category */
};


static GaimPluginInfo info = {
  GAIM_PLUGIN_API_VERSION,        /**< api_version    */
  GAIM_PLUGIN_PROTOCOL,           /**< type           */
  NULL,                           /**< ui_requirement */
  0,                              /**< flags          */
  NULL,                           /**< dependencies   */
  GAIM_PRIORITY_DEFAULT,          /**< priority       */
  
  PLUGIN_ID,                      /**< id             */
  PLUGIN_NAME,                    /**< name           */
  PLUGIN_VERSION,                 /**< version        */
  PLUGIN_SUMMARY,                 /**  summary        */
  PLUGIN_DESC,                    /**  description    */
  PLUGIN_AUTHOR,                  /**< author         */
  PLUGIN_HOMEPAGE,                /**< homepage       */
  
  NULL,                           /**< load           */
  NULL,                           /**< unload         */
  NULL,                           /**< destroy        */
  NULL,                           /**< ui_info        */
  &prpl_info,                     /**< extra_info     */
  NULL,                           /**< prefs info     */
  NULL                            /**< actions        */
};


static void init_plugin(GaimPlugin *plugin) {
  GaimAccountOption *opt;
  
  opt = gaim_account_option_string_new("Server", MW_KEY_HOST,
				       PLUGIN_DEFAULT_HOST);
  prpl_info.protocol_options = g_list_append(prpl_info.protocol_options, opt);
  
  opt = gaim_account_option_int_new("Port", MW_KEY_PORT, PLUGIN_DEFAULT_PORT);
  prpl_info.protocol_options = g_list_append(prpl_info.protocol_options, opt);

  meanwhile_plugin = plugin;
}


GAIM_INIT_PLUGIN(meanwhile, init_plugin, info)


