
/*
  Meanwhile Protocol Plugin for Gaim
  Adds Lotus Sametime support to Gaim using the Meanwhile library

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

#ifndef _GAIM_MIME_H
#define _GAIM_MIME_H


#include <glib.h>
#include <glib/glist.h>


/** @file mime.h

    Rudimentary parsing of multi-part MIME messages into more
    accessible structures.

    Hopefully this might get included into Gaim directly at some
    point. But until then it's just a piece of the Meanwhile plugin.
*/


/** @typedef GaimMimeDocument
    A MIME document
 */
typedef struct _GaimMimeDocument GaimMimeDocument;


/** @typedef GaimMimePart
    A part of a multipart MIME document
 */
typedef struct _GaimMimePart GaimMimePart;


/** Allocate an empty MIME document */
GaimMimeDocument *gaim_mime_document_new();


/** Parse a MIME document from a NUL-terminated string
    @param doc  the MIME Document
    @param buf  the NUL-terminated string containing the MIME-encoded data
 */
void gaim_mime_document_parse(GaimMimeDocument *doc, const char *buf);


/** Parse a MIME document from a string
    @param doc  the MIME Document
    @param buf  the string containing the MIME-encoded data
    @param len  length of buf
 */
void gaim_mime_document_parse_len(GaimMimeDocument *doc,
				  const char *buf, gsize len);


/** The list of fields in the header of a document
    @param doc  the MIME document
    @returns    list of strings indicating the fields (but not the values of
                the fields) in the header of doc
*/
const GList *gaim_mime_document_get_fields(GaimMimeDocument *doc);


/** Get the value of a specific field in the header of a document
    @param doc    the MIME document
    @param field  case-insensitive field name
    @returns      value associated with the indicated header field, or
                  NULL if the field doesn't exist
*/
const char *gaim_mime_document_get_field(GaimMimeDocument *doc,
					 const char *field);


/** The list of parts in a multipart document
    @param doc   the MIME document
    @returns     list of GaimMimePart contained within doc
*/
const GList *gaim_mime_document_get_parts(GaimMimeDocument *doc);


/** Frees memory used in a MIME document and all of its parts and fields
    @param doc   the MIME document to free
 */
void gaim_mime_document_free(GaimMimeDocument *doc);


/** The list of fields in the header of a document part
    @param part  the MIME document part
    @returns  list of strings indicating the fields (but not the values
              of the fields) in the header of part
*/
const GList *gaim_mime_part_get_fields(GaimMimePart *part);


/** Get the value of a specific field in the header of a document part
    @param part   the MIME document part
    @param field  case-insensitive name of the header field
    @returns      value of the specified header field, or NULL if the
                  field doesn't exist
*/
const char *gaim_mime_part_get_field(GaimMimePart *part,
				     const char *field);


/** Get the (possibly encoded) data portion of a MIME document part
    @param part   the MIME document part
    @returns      NUL-terminated data found in the document part
 */
const char *gaim_mime_part_get_data(GaimMimePart *part);


/** Get the length of the data portion of a MIME document part
    @param part  the MIME document part
    @returns     length of the data in the document part
*/
gsize gaim_mime_part_get_length(GaimMimePart *part);


#endif
