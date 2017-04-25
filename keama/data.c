/*
 * Copyright (c) 2017 by Internet Systems Consortium, Inc. ("ISC")
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND ISC DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS.  IN NO EVENT SHALL ISC BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT
 * OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 *   Internet Systems Consortium, Inc.
 *   950 Charter Street
 *   Redwood City, CA 94063
 *   <info@isc.org>
 *   http://www.isc.org/
 */

#include "data.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>

struct string *
allocString(void)
{
	struct string *result;

	result = (struct string *)malloc(sizeof(struct string));
	assert(result != NULL);
	memset(result, 0, sizeof(struct string));

	return result;
}

struct string *
makeString(int l, const char *s)
{
	struct string *result;

	result = allocString();
	if (l < 0)
		result->length = strlen(s);
	else
		result->length = (size_t)l;
	if (result->length > 0) {
		result->content = (char *)malloc(result->length + 1);
		assert(result->content != NULL);
		memcpy(result->content, s, result->length);
		result->content[result->length] = 0;
	}

	return result;
}

void
appendString(struct string *s, const char *a)
{
	size_t n;

	assert(s != NULL);

	if (a == NULL)
		return;
	n = strlen(a);
	if (n == 0)
		return;
	s->content = (char *)realloc(s->content, s->length + n + 1);
	assert(s->content != NULL);
	memcpy(s->content + s->length, a, n);
	s->length += n;
	s->content[s->length] = 0;
}

void
concatString(struct string *s, const struct string *a)
{
	assert(s != NULL);
	assert(a != NULL);

	s->content = (char *)realloc(s->content, s->length + a->length + 1);
	assert(s->content != NULL);
	memcpy(s->content + s->length, a->content, a->length);
	s->length += a->length;
	s->content[s->length] = 0;
}

isc_boolean_t
eqString(const struct string *s, const struct string *o)
{
	assert(s != NULL);
	assert(o != NULL);

	if (s->length != o->length)
		return ISC_FALSE;
	if (s->length == 0)
		return ISC_TRUE;
	return ISC_TF(memcmp(s->content, o->content, s->length) == 0);
}

struct comment *
createComment(const char *line)
{
	struct comment *comment;

	assert(line != NULL);

	comment = (struct comment *)malloc(sizeof(struct comment));
	assert(comment != NULL);
	memset(comment, 0, sizeof(struct comment));

	comment->line = strdup(line);

	return comment;
}

int64_t
intValue(const struct element *e)
{
	assert(e != NULL);
	assert(e->type == ELEMENT_INTEGER);
	return e->value.int_value;
}

double
doubleValue(const struct element *e)
{
	assert(e != NULL);
	assert(e->type == ELEMENT_REAL);
	return e->value.double_value;
}

isc_boolean_t
boolValue(const struct element *e)
{
	assert(e != NULL);
	assert(e->type == ELEMENT_BOOLEAN);
	/* could check if 0 or 1 */
	return e->value.bool_value;
}

struct string *
stringValue(struct element *e)
{
	assert(e != NULL);
	assert(e->type == ELEMENT_STRING);
	return &e->value.string_value;
}

struct list *
listValue(struct element *e)
{
	assert(e != NULL);
	assert(e->type == ELEMENT_LIST);
	return &e->value.list_value;
}

struct map *
mapValue(struct element *e)
{
	assert(e != NULL);
	assert(e->type == ELEMENT_MAP);
	return &e->value.map_value;
}

struct element *
create(void)
{
	struct element *elem;

	elem = (struct element *)malloc(sizeof(struct element));
	assert(elem != NULL);
	memset(elem, 0, sizeof(struct element));
	TAILQ_INIT(&elem->comments);

	return elem;
}

struct element *
createInt(int64_t i)
{
	struct element *elem;

	elem = create();
	elem->type = ELEMENT_INTEGER;
	elem->value.int_value = i;

	return elem;
}

struct element *
createDouble(double d)
{
	struct element *elem;

	elem = create();
	elem->type = ELEMENT_REAL;
	elem->value.double_value = d;

	return elem;
}

struct element *
createBool(isc_boolean_t b)
{
	struct element *elem;

	elem = create();
	elem->type = ELEMENT_BOOLEAN;
	elem->value.bool_value = b;

	return elem;
}

struct element *
createNull(void)
{
	struct element *elem;

	elem = create();
	elem->type = ELEMENT_NULL;

	return elem;
}

struct element *
createString(const struct string *s)
{
	struct element *elem;

	elem = create();
	elem->type = ELEMENT_STRING;
	elem->value.string_value = *s;

	return elem;
}

struct element *
createList(void)
{
	struct element *elem;

	elem = create();
	elem->type = ELEMENT_LIST;
	TAILQ_INIT(&elem->value.list_value);

	return elem;
}

struct element *
createMap(void)
{
	struct element *elem;

	elem = create();
	elem->type = ELEMENT_MAP;
	TAILQ_INIT(&elem->value.map_value);

	return elem;
}

static void
reset(struct element *e)
{
	e->type = 0;
	e->kind = 0;
	assert(e->key == NULL);
	memset(&e->value, 0, sizeof(e->value));
}

void
resetInt(struct element *e, int64_t i)
{
	assert(e != NULL);

	reset(e);
	e->type = ELEMENT_INTEGER;
	e->value.int_value = i;
}
	
void
resetDouble(struct element *e, double d)
{
	assert(e != NULL);

	reset(e);
	e->type = ELEMENT_REAL;
	e->value.double_value = d;
}

void
resetBool(struct element *e, isc_boolean_t b)
{
	assert(e != NULL);

	reset(e);
	e->type = ELEMENT_BOOLEAN;
	e->value.bool_value = b;
}

void resetNull(struct element *e)
{
	assert(e != NULL);

	reset(e);
	e->type = ELEMENT_NULL;
}

void
resetString(struct element *e, const struct string *s)
{
	assert(e != NULL);

	reset(e);
	e->type = ELEMENT_STRING;
	e->value.string_value = *s;
}

void
resetList(struct element *e)
{
	assert(e != NULL);

	reset(e);
	e->type = ELEMENT_LIST;
	TAILQ_INIT(&e->value.list_value);
}

void
resetMap(struct element *e)
{
	assert(e != NULL);

	reset(e);
	e->type = ELEMENT_MAP;
	TAILQ_INIT(&e->value.map_value);
}

void
resetBy(struct element *e, struct element *o)
{
	assert(e != NULL);
	assert(o != NULL);

	reset(e);
	e->type = o->type;
	e->kind = o->kind;
	e->skip = o->skip;
	e->key = o->key;
	o->key = NULL;
	TAILQ_CONCAT(&e->comments, &o->comments);

	switch (e->type) {
	case ELEMENT_INTEGER:
		e->value.int_value = o->value.int_value;
		break;
	case ELEMENT_REAL:
		e->value.double_value = o->value.double_value;
		break;
	case ELEMENT_BOOLEAN:
		e->value.bool_value = o->value.bool_value;
		break;
	case ELEMENT_STRING:
		e->value.string_value = o->value.string_value;
		break;
	case ELEMENT_LIST:
		TAILQ_INIT(&e->value.list_value);
		TAILQ_CONCAT(&e->value.list_value, &o->value.list_value);
		break;
	case ELEMENT_MAP:
		TAILQ_INIT(&e->value.map_value);
		TAILQ_CONCAT(&e->value.map_value, &o->value.map_value);
		break;
	default:
		assert(0);
	}
	reset(o);
}

struct element *
listGet(struct element *l, int i)
{
	struct element *elem;

	assert(l != NULL);
	assert(l->type == ELEMENT_LIST);
	assert(i >= 0);

	elem = TAILQ_FIRST(&l->value.list_value);
	assert(elem != NULL);
	assert(elem->key == NULL);

	for (unsigned j = i; j > 0; --j) {
		elem = TAILQ_NEXT(elem);
		assert(elem != NULL);
		assert(elem->key == NULL);
	}

	return elem;
}

void
listSet(struct element *l, struct element *e, int i)
{
	assert(l != NULL);
	assert(l->type == ELEMENT_LIST);
	assert(e != NULL);
	assert(i >= 0);

	if (i == 0) {
		TAILQ_INSERT_HEAD(&l->value.list_value, e);
	} else {
		struct element *prev;
		
		prev = TAILQ_FIRST(&l->value.list_value);
		assert(prev != NULL);
		assert(prev->key == NULL);

		for (unsigned j = i; j > 1; --j) {
			prev = TAILQ_NEXT(prev);
			assert(prev != NULL);
			assert(prev->key == NULL);
		}

		TAILQ_INSERT_AFTER(&l->value.list_value, prev, e);
	}
}

void
listPush(struct element *l, struct element *e)
{
	assert(l != NULL);
	assert(l->type == ELEMENT_LIST);
	assert(e != NULL);

	TAILQ_INSERT_TAIL(&l->value.list_value, e);
}

void
listRemove(struct element *l, int i)
{
	struct element *elem;

	assert(l != NULL);
	assert(l->type == ELEMENT_LIST);
	assert(i >= 0);

	elem = TAILQ_FIRST(&l->value.list_value);
	assert(elem != NULL);
	assert(elem->key == NULL);

	for (unsigned j = i; j > 0; --j) {
		elem = TAILQ_NEXT(elem);
		assert(elem != NULL);
		assert(elem->key == NULL);
	}

	TAILQ_REMOVE(&l->value.list_value, elem);
}

size_t
listSize(const struct element *l)
{
	struct element *elem;
	size_t cnt;

	assert(l != NULL);
	assert(l->type == ELEMENT_LIST);

	cnt = 0;
	TAILQ_FOREACH(elem, &l->value.list_value) {
		assert(elem->key == NULL);
		cnt++;
	}

	return cnt;
}

void
concat(struct element *l, struct element *o)
{
	assert(l != NULL);
	assert(l->type == ELEMENT_LIST);
	assert(o != NULL);
	assert(o->type == ELEMENT_LIST);

	TAILQ_CONCAT(&l->value.list_value, &o->value.list_value);
}

struct element *
mapGet(struct element *m, const char *k)
{
	struct element *elem;

	assert(m != NULL);
	assert(m->type == ELEMENT_MAP);
	assert(k != NULL);

	TAILQ_FOREACH(elem, &m->value.map_value) {
		assert(elem->key != NULL);
		if (strcmp(elem->key, k) == 0)
			break;
	}

	return elem;
}

void
mapSet(struct element *m, struct element *e, const char *k)
{
	assert(m != NULL);
	assert(m->type == ELEMENT_MAP);
	assert(e != NULL);
	assert(k != NULL);
#if 0
	assert(mapGet(m, k) == NULL);
#endif
	e->key = strdup(k);
	assert(e->key != NULL);
	TAILQ_INSERT_TAIL(&m->value.map_value, e);
}

void
mapRemove(struct element *m, const char *k)
{
	struct element *elem;

	assert(m != NULL);
	assert(m->type == ELEMENT_MAP);
	assert(k != NULL);

	TAILQ_FOREACH(elem, &m->value.map_value) {
		assert(elem->key != NULL);
		if (strcmp(elem->key, k) == 0)
			break;
	}

	assert(elem != NULL);
	TAILQ_REMOVE(&m->value.map_value, elem);
}

isc_boolean_t
mapContains(const struct element *m, const char *k)
{
	struct element *elem;

	assert(m != NULL);
	assert(m->type == ELEMENT_MAP);
	assert(k != NULL);

	TAILQ_FOREACH(elem, &m->value.map_value) {
		assert(elem->key != NULL);
		if (strcmp(elem->key, k) == 0)
			break;
	}

	return ISC_TF(elem != NULL);
}

size_t
mapSize(const struct element *m)
{
	struct element *elem;
	size_t cnt;

	assert(m != NULL);
	assert(m->type == ELEMENT_MAP);

	cnt = 0;
	TAILQ_FOREACH(elem, &m->value.map_value) {
		assert(elem->key != NULL);
		cnt++;
	}

	return cnt;
}

void
merge(struct element *m, struct element *o)
{
	struct element *elem;
	struct element *ne;

	assert(m != NULL);
	assert(m->type == ELEMENT_MAP);
	assert(o != NULL);
	assert(o->type == ELEMENT_MAP);

	TAILQ_FOREACH_SAFE(elem, &o->value.map_value, ne) {
		assert(elem->key != NULL);
		TAILQ_REMOVE(&o->value.map_value, elem);
		if (!mapContains(m, elem->key)) {
			TAILQ_INSERT_TAIL(&m->value.map_value, elem);
		}
	}
}

const char *
type2name(int t)
{
	switch (t) {
	case ELEMENT_NONE:
		return "not initialized?";
	case ELEMENT_INTEGER:
		return "integer";
	case ELEMENT_REAL:
		return "real";
	case ELEMENT_BOOLEAN:
		return "boolean";
	case ELEMENT_NULL:
		return "(unused) null";
	case ELEMENT_STRING:
		return "string";
	case ELEMENT_LIST:
		return "list";
	case ELEMENT_MAP:
		return "map";
	default:
#if 0
		assert(0);
#endif
		return "unknown?";
	}
}

int
name2type(const char *n)
{
	assert(n != NULL);
	if (strcmp(n, "integer") == 0)
		return ELEMENT_INTEGER;
	if (strcmp(n, "real") == 0)
		return ELEMENT_REAL;
	if (strcmp(n, "boolean") == 0)
		return ELEMENT_BOOLEAN;
	if (strcmp(n, "null") == 0)
		return ELEMENT_NULL;
	if (strcmp(n, "string") == 0)
		return ELEMENT_STRING;
	if (strcmp(n, "list") == 0)
		return ELEMENT_LIST;
	if (strcmp(n, "map") == 0)
		return ELEMENT_MAP;
#if 0
	assert(0);
#endif
	return ELEMENT_NONE;
}

void
print(FILE *fp, const struct element *e, isc_boolean_t skip, unsigned indent)
{
	assert(fp != NULL);
	assert(e != NULL);

	switch (e->type) {
	case ELEMENT_LIST:
		printList(fp, &e->value.list_value, skip, indent);
		return;
	case ELEMENT_MAP:
		printMap(fp, &e->value.map_value, skip, indent);
		return;
	case ELEMENT_STRING:
		printString(fp, &e->value.string_value);
		return;
	case ELEMENT_INTEGER:
		fprintf(fp, "%lld", (long long)e->value.int_value);
		return;
	case ELEMENT_REAL:
		fprintf(fp, "%f", e->value.double_value);
		return;
	case ELEMENT_BOOLEAN:
		if (e->value.bool_value)
			fprintf(fp, "true");
		else
			fprintf(fp, "false");
		return;
	case ELEMENT_NULL:
		fprintf(fp, "null");
		return;
	default:
		assert(0);
	}
}

static void
addIndent(FILE *fp, int skip, unsigned indent)
{
	unsigned sp;

	if (skip) {
		fprintf(fp, "//");
		if (indent > 2)
			for (sp = 0; sp < indent - 2; ++sp)
				fprintf(fp, " ");
	} else
		for (sp = 0; sp < indent; ++sp)
			fprintf(fp, " ");
}	

void
printList(FILE *fp, const struct list *l, isc_boolean_t skip, unsigned indent)
{
	struct element *elem;
	struct comment *comment;
	isc_boolean_t first;

	assert(fp != NULL);
	assert(l != NULL);

	if (TAILQ_EMPTY(l)) {
		fprintf(fp, "[ ]");
		return;
	}

	fprintf(fp, "[\n");
	first = ISC_TRUE;
	TAILQ_FOREACH(elem, l) {
		isc_boolean_t skip_elem = skip;

		assert(elem->key == NULL);
		if (!skip) {
			skip_elem = elem->skip;
			if (skip_to_end(elem)) {
				if (!first)
					fprintf(fp, "\n");
				first = ISC_TRUE;
			}
		}
		if (!first)
			fprintf(fp, ",\n");
		first = ISC_FALSE;
		TAILQ_FOREACH(comment, &elem->comments) {
			addIndent(fp, skip_elem, indent + 2);
			fprintf(fp, "%s\n", comment->line);
		}
		addIndent(fp, skip_elem, indent + 2);
		print(fp, elem, skip_elem, indent + 2);
	}
	fprintf(fp, "\n");
	addIndent(fp, skip, indent);
	fprintf(fp, "]");
}

void
printMap(FILE *fp, const struct map *m, isc_boolean_t skip, unsigned indent)
{
	struct element *elem;
	struct comment *comment;
	isc_boolean_t first;

	assert(fp != NULL);
	assert(m != NULL);

	if (TAILQ_EMPTY(m)) {
		fprintf(fp, "{ }");
		return;
	}

	fprintf(fp, "{\n");
	first = ISC_TRUE;
	TAILQ_FOREACH(elem, m) {
		isc_boolean_t skip_elem = skip;

		assert(elem->key != NULL);
		if (!skip) {
			skip_elem = elem->skip;
			if (skip_to_end(elem)) {
				if (!first)
					fprintf(fp, "\n");
				first = ISC_TRUE;
			}
		}
		if (!first)
			fprintf(fp, ",\n");
		first = ISC_FALSE;
		TAILQ_FOREACH(comment, &elem->comments) {
			addIndent(fp, skip_elem, indent + 2);
			fprintf(fp, "%s\n", comment->line);
		}
		addIndent(fp, skip_elem, indent + 2);
		fprintf(fp, "\"%s\": ", elem->key);
		print(fp, elem, skip_elem, indent + 2);
	}
	fprintf(fp, "\n");
	addIndent(fp, skip, indent);
	fprintf(fp, "}");
}

void
printString(FILE *fp, const struct string *s)
{
	size_t i;

	assert(fp != NULL);
	assert(s != NULL);

	fprintf(fp, "\"");
	for (i = 0; i < s->length; ++i) {
		char c = *(s->content + i);

		switch (c) {
		case '"':
			fprintf(fp, "\\\"");
			break;
		case '\\':
			fprintf(fp, "\\\\");
			break;
		case '\b':
			fprintf(fp, "\\b");
			break;
		case '\f':
			fprintf(fp, "\\f");
			break;
		case '\n':
			fprintf(fp, "\\n");
			break;
		case '\r':
			fprintf(fp, "\\r");
			break;
		case '\t':
			fprintf(fp, "\\t");
			break;
		default:
			if ((c >= 0) && (c < 0x20)) {
				fprintf(fp, "\\u%04x", (unsigned)c & 0xff);
			} else {
				fprintf(fp, "%c", c);
			}
		}
	}
	fprintf(fp, "\"");
}

isc_boolean_t
skip_to_end(const struct element *e)
{
	do {
		if (!e->skip)
			return ISC_FALSE;
		e = TAILQ_NEXT(e);
	} while (e != NULL);
	return ISC_TRUE;
}

struct element *
copy(struct element *e)
{
	struct element *result;
	struct comment *comment;

	assert(e != NULL);

	switch (e->type) {
	case ELEMENT_INTEGER:
		result = createInt(intValue(e));
		break;
	case ELEMENT_REAL:
		result = createDouble(doubleValue(e));
		break;
	case ELEMENT_BOOLEAN:
		result = createBool(boolValue(e));
		break;
	case ELEMENT_NULL:
		result = createNull();
		break;
	case ELEMENT_STRING:
		result = createString(stringValue(e));
		break;
	case ELEMENT_LIST:
		result = copyList(e);
		break;
	case ELEMENT_MAP:
		result = copyMap(e);
		break;
	default:
		assert(0);
	}
	result->kind = e->kind;
	result->skip = e->skip;
	/* don't copy key */
	/* copy comments */
	TAILQ_FOREACH(comment, &e->comments) {
		comment = createComment(comment->line);
		TAILQ_INSERT_TAIL(&result->comments, comment);
	}
	return result;
}

struct element *
copyList(struct element *l)
{
	struct element *result;
	size_t i;

	result = createList();
	for (i = 0; i < listSize(l); i++)
		listPush(result, copy(listGet(l, i)));
	return result;
}

struct element *
copyMap(struct element *m)
{
	struct element *result;
	struct element *item;

	result = createMap();
	TAILQ_FOREACH(item, &m->value.map_value)
		mapSet(result, copy(item), item->key);
	return result;
}

struct handle *
mapPop(struct element *m)
{
	struct element *item;
	struct handle *h;

	assert(m != NULL);
	assert(m->type == ELEMENT_MAP);

	h = (struct handle *)malloc(sizeof(struct handle));
	assert(h != NULL);
	memset(h, 0, sizeof(struct handle));
	TAILQ_INIT(&h->values);

	item = TAILQ_FIRST(&m->value.map_value);
	assert(item != NULL);
	assert(item->key != NULL);
	h->key = strdup(item->key);
	assert(h->key != NULL);
	h->value = item;

	TAILQ_REMOVE(&m->value.map_value, item);

	return h;
}

void
derive(struct handle *src, struct handle *dst)
{
	struct element *list;
	struct element *item;
	size_t i;

	if (dst == NULL)
		return;
	list = dst->value;
	assert(list != NULL);
	assert(list->type == ELEMENT_LIST);
	for (i = 0; i < listSize(list); i++) {
		item = listGet(list, i);
		assert(item != NULL);
		assert(item->type == ELEMENT_MAP);
		if (mapContains(item, src->key))
			continue;
		mapSet(item, copy(src->value), src->key);
	}
}
