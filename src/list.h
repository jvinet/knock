/*
 *  list.h
 * 
 *  Copyright (c) 2002-2005 by Judd Vinet <jvinet@zeroflux.org>
 * 
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, 
 *  USA.
 */
#ifndef _PAC_LIST_H
#define _PAC_LIST_H

#define FREELIST(p) { list_free(p); p = NULL; }

/* your average linked list */
typedef struct __pmlist_t {
	void*   data;
	struct __pmlist_t* prev;
	struct __pmlist_t* next;
} PMList;

PMList* list_new();
void list_free(PMList* list);
PMList* list_add(PMList* list, void* data);
PMList* list_remove(PMList* list, void* data);
int list_count(PMList* list);
int list_isin(PMList *haystack, void *needle);
int is_in(char *needle, PMList *haystack);
PMList* list_merge(PMList *one, PMList *two);
PMList* list_last(PMList* list);
int list_strcmp(const void *s1, const void *s2);
PMList *list_sort(PMList *list);
void list_display(const char *title, PMList *list);

#endif

/* vim: set ts=2 sw=2 noet: */
