
#ifndef _GAIM_MIME_H
#define _GAIM_MIME_H


#include <glib.h>
#include <glib/glist.h>


/** @typedef GaimMimeDocument */
typedef struct _GaimMimeDocument GaimMimeDocument;


/** @typedef GaimMimePart */
typedef struct _GaimMimePart GaimMimePart;


GaimMimeDocument *gaim_mime_document_new();


void gaim_mime_document_parse(GaimMimeDocument *doc, const char *buf);


void gaim_mime_document_parse_len(GaimMimeDocument *doc,
				  const char *buf, gsize len);


const GList *gaim_mime_document_get_fields(GaimMimeDocument *doc);


const char *gaim_mime_document_get_field(GaimMimeDocument *doc,
					 const char *field);


const GList *gaim_mime_document_get_parts(GaimMimeDocument *doc);


void gaim_mime_document_free(GaimMimeDocument *doc);


const GList *gaim_mime_part_get_fields(GaimMimePart *part);


const char *gaim_mime_part_get_field(GaimMimePart *part,
				     const char *field);


const char *gaim_mime_part_get_data(GaimMimePart *part);


#endif
