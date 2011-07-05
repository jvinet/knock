/*
 *  list.c
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

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "list.h"

PMList* list_new()
{
	PMList *list = NULL;
	
	list = (PMList*)malloc(sizeof(PMList));
	if(list == NULL) {
		return(NULL);
	}
	list->data = NULL;
	list->prev = NULL;
	list->next = NULL;
	return(list);
}

void list_free(PMList *list)
{
	if(list == NULL) {
		return;
	}
	if(list->data != NULL) {
		free(list->data);
		list->data = NULL;
	}
	if(list->next != NULL) {
		list_free(list->next);
	}
	free(list);
	return;
}

PMList* list_add(PMList *list, void *data)
{
	PMList *ptr, *lp;

	ptr = list;
	if(ptr == NULL) {
		ptr = list_new();
	}

	lp = list_last(ptr);
	if(lp == ptr && lp->data == NULL) {
		/* nada */
	} else {
		lp->next = list_new();
		if(lp->next == NULL) {
			return(NULL);
		}
		lp->next->prev = lp;
		lp = lp->next;
	}
	lp->data = data;
	return(ptr);
}

PMList* list_remove(PMList* list, void* data)
{
	PMList *ptr, *lp;

	ptr = list;

	for(lp = list; lp; lp = lp->next) {
		if(lp->data == data) {
			if(lp->prev != NULL) {
				lp->prev->next = lp->next;
			}
			if(lp->next != NULL) {
				lp->next->prev = lp->prev;
			}
			/* test if we just removed the head */
			if(lp == ptr) {
				ptr = lp->next;
			}
		}
	}
	return ptr;
}

int list_count(PMList *list)
{
	int i;
	PMList *lp;

	for(lp = list, i = 0; lp; lp = lp->next, i++);
	return(i);
}

int list_isin(PMList *haystack, void *needle)
{
	PMList *lp;

	for(lp = haystack; lp; lp = lp->next) {
		if(lp->data == needle) {
			return(1);
		}
	}
	return(0);
}

/* Test for existence of a string in a PMList
 */
int is_in(char *needle, PMList *haystack)
{
	PMList *lp;

	for(lp = haystack; lp; lp = lp->next) {
		if(lp->data && !strcmp(lp->data, needle)) {
			return(1);
		}
	}
	return(0);
}

/* List one is extended and returned
 */
PMList* list_merge(PMList *one, PMList *two)
{
	PMList *lp, *ptr;

	if(two == NULL) {
		return one;
	}

	ptr = one;
	if(ptr == NULL) {
		ptr = list_new();
	}

	for(lp = two; lp; lp = lp->next) {
		if(lp->data) {
			ptr = list_add(ptr, lp->data);
			lp->data = NULL;
		}
	}

	return(ptr);
}

PMList* list_last(PMList *list)
{
	PMList *ptr;

	for(ptr = list; ptr && ptr->next; ptr = ptr->next);
	return(ptr);
}

/* Helper function for sorting a list of strings
 */
int list_strcmp(const void *s1, const void *s2)
{
	char **str1 = (char **)s1;
	char **str2 = (char **)s2;

	return(strcmp(*str1, *str2));
}

PMList *list_sort(PMList *list)
{
	char **arr = NULL;
	PMList *lp;
	unsigned int arrct;
	int i;

	if(list == NULL) {
		return(NULL);
	}

	arrct = list_count(list);
	arr = (char **)malloc(arrct*sizeof(char*));
	for(lp = list, i = 0; lp; lp = lp->next) {
		arr[i++] = (char *)lp->data;
	}

	qsort(arr, (size_t)arrct, sizeof(char *), list_strcmp);

	lp = NULL;
	for(i = 0; i < arrct; i++) {
		lp = list_add(lp, strdup(arr[i]));
	}

	if(arr) {
		free(arr);
		arr = NULL;
	}

	return(lp);
}

void list_display(const char *title, PMList *list)
{
	PMList *lp;
	int cols, len, maxcols = 80;
	char *cenv = NULL;

	cenv = getenv("COLUMNS");
	if(cenv) {
		maxcols = atoi(cenv);
	}

	len = strlen(title);
	printf("%s ", title);

	if(list) {
		for(lp = list, cols = len; lp; lp = lp->next) {
			int s = strlen((char*)lp->data)+1;
			if(s+cols >= maxcols) {
				int i;
				cols = len;
				printf("\n");
				for (i = 0; i < len+1; i++) {
					printf(" ");
				}
			}
			printf("%s ", (char*)lp->data);
			cols += s;
		}
		printf("\n");
	} else {
		printf("None\n");
	}
}

/* vim: set ts=2 sw=2 noet: */
