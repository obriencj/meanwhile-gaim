
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


#define PLUGIN_ID        "prpl-meanwhile"
#define PLUGIN_NAME      "Meanwhile"
#define PLUGIN_SUMMARY   "Meanwhile Protocol Plugin"
#define PLUGIN_DESC      "Open implementation of a Lotus Sametime client"
#define PLUGIN_AUTHOR    "Christopher J O'Brien <obriencj@us.ibm.com>"
#define PLUGIN_HOMEPAGE  "http://w3.opensource.ibm.com/~meanwhile"

#define MW_CONNECT_STEPS  7
#define MW_CONNECT_1  _("Looking up server")
#define MW_CONNECT_2  _("Sending Handshake")
#define MW_CONNECT_3  _("Waiting for Handshake Acknowledgement")
#define MW_CONNECT_4  _("Handshake Acknowledged, Sending Login")
#define MW_CONNECT_5  _("Waiting for Login Acknowledgement")
#define MW_CONNECT_6  _("Login Acknowledged")

#define UC_NORMAL  0x10

#define MW_STATE_OFFLINE  _("Offline")
#define MW_STATE_ACTIVE   _("Active")
#define MW_STATE_AWAY     _("Away")
#define MW_STATE_BUSY     _("Do Not Disturb")
#define MW_STATE_IDLE     _("Idle")
#define MW_STATE_UNKNOWN  _("Unknown")

#define CHAT_CREATOR_KEY  "chat_creator"
#define CHAT_NAME_KEY     "chat_name"
#define CHAT_TOPIC_KEY    "chat_topic"
#define CHAT_INVITE_KEY   "chat_invite"


/* keys to get gaim plugin information */
#define MW_KEY_HOST       "server"
#define MW_KEY_PORT       "port"
#define MW_KEY_COMMUNITY  "community"


/* default host and port for the gaim plugin */
#ifndef PLUGIN_DEFAULT_HOST
#define PLUGIN_DEFAULT_HOST       ""
#endif

#define PLUGIN_DEFAULT_PORT       1533


/* the amount of data the plugin will attempt to read from a socket in a
   single call. Note that it's signed. */
#define READ_BUFFER_SIZE  1024


/* default inactivity threshold for the gaim plugin to pass to
   mwChannel_destroyInactive. length in seconds */
#define INACTIVE_THRESHOLD 30
