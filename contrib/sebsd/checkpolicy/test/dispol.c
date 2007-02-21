
/* Authors: Frank Mayer <mayerf@tresys.com> and Karl MacMillan <kmacmillan@tresys.com>
 *
 * Copyright (C) 2003 Tresys Technology, LLC
 *	This program is free software; you can redistribute it and/or modify
 *  	it under the terms of the GNU General Public License as published by
 *	the Free Software Foundation, version 2.
 */

/* 
 * displaypol.c
 *
 * Test program to the contents of a binary policy in text
 * form.  This program currently only displays the
 * avtab (including conditional avtab) rules.
 *
 * 	displaypol binary_pol_file
 */

#include <sepol/policydb/policydb.h>
#include <sepol/policydb/avtab.h>
#include <sepol/policydb/services.h>
#include <sepol/policydb/conditional.h>
#include <sepol/policydb/expand.h>
#include <sepol/policydb/util.h>
#include <getopt.h>
#include <assert.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <errno.h>
#include <stdio.h>
#include <fcntl.h>

static policydb_t policydb;

void usage(char *progname)
{
	printf("usage:  %s binary_pol_file\n\n", progname);
	exit(1);
}

int render_access_mask(uint32_t mask, avtab_key_t * key, policydb_t * p,
		       FILE * fp)
{
	char *perm;
	fprintf(fp, "{");
	perm = sepol_av_to_string(p, key->target_class, mask);
	if (perm)
		fprintf(fp, "%s ", perm);
	fprintf(fp, "}");
	return 0;
}

int render_type(uint32_t type, policydb_t * p, FILE * fp)
{
	fprintf(fp, "%s", p->p_type_val_to_name[type - 1]);
	return 0;
}

int render_key(avtab_key_t * key, policydb_t * p, FILE * fp)
{
	char *stype, *ttype, *tclass;
	stype = p->p_type_val_to_name[key->source_type - 1];
	ttype = p->p_type_val_to_name[key->target_type - 1];
	tclass = p->p_class_val_to_name[key->target_class - 1];
	if (stype && ttype)
		fprintf(fp, "%s %s : %s ", stype, ttype, tclass);
	else if (stype)
		fprintf(fp, "%s %u : %s ", stype, key->target_type, tclass);
	else if (ttype)
		fprintf(fp, "%u %s : %s ", key->source_type, ttype, tclass);
	else
		fprintf(fp, "%u %u : %s ", key->source_type, key->target_type,
			tclass);
	return 0;
}

/* 'what' values for this function */
#define	RENDER_UNCONDITIONAL	0x0001	/* render all regardless of enabled state */
#define RENDER_ENABLED		0x0002
#define RENDER_DISABLED		0x0004
#define RENDER_CONDITIONAL	(RENDER_ENABLED|RENDER_DISABLED)

int render_av_rule(avtab_key_t * key, avtab_datum_t * datum, uint32_t what,
		   policydb_t * p, FILE * fp)
{
	if (!(what & RENDER_UNCONDITIONAL)) {
		if (what != RENDER_CONDITIONAL && (((what & RENDER_ENABLED)
						    && !(key->
							 specified &
							 AVTAB_ENABLED))
						   || ((what & RENDER_DISABLED)
						       && (key->
							   specified &
							   AVTAB_ENABLED)))) {
			return 0;	/* doesn't match selection criteria */
		}
	}

	if (!(what & RENDER_UNCONDITIONAL)) {
		if (key->specified & AVTAB_ENABLED)
			fprintf(fp, "[enabled] ");
		else if (!(key->specified & AVTAB_ENABLED))
			fprintf(fp, "[disabled] ");
	}

	if (key->specified & AVTAB_AV) {
		if (key->specified & AVTAB_ALLOWED) {
			fprintf(fp, "allow ");
			render_key(key, p, fp);
			render_access_mask(datum->data, key, p, fp);
			fprintf(fp, ";\n");
		}
		if (key->specified & AVTAB_AUDITALLOW) {
			fprintf(fp, "auditallow ");
			render_key(key, p, fp);
			render_access_mask(datum->data, key, p, fp);
			fprintf(fp, ";\n");
		}
		if (key->specified & AVTAB_AUDITDENY) {
			fprintf(fp, "dontaudit ");
			render_key(key, p, fp);
			/* We inverse the mask for dontaudit since the mask is internally stored
			 * as a auditdeny mask */
			render_access_mask(~datum->data, key, p, fp);
			fprintf(fp, ";\n");
		}
	} else if (key->specified & AVTAB_TYPE) {
		if (key->specified & AVTAB_TRANSITION) {
			fprintf(fp, "type_transition ");
			render_key(key, p, fp);
			render_type(datum->data, p, fp);
			fprintf(fp, ";\n");
		}
		if (key->specified & AVTAB_MEMBER) {
			fprintf(fp, "type_member ");
			render_key(key, p, fp);
			render_type(datum->data, p, fp);
			fprintf(fp, ";\n");
		}
		if (key->specified & AVTAB_CHANGE) {
			fprintf(fp, "type_change ");
			render_key(key, p, fp);
			render_type(datum->data, p, fp);
			fprintf(fp, ";\n");
		}
	} else {
		fprintf(fp, "     ERROR: no valid rule type specified\n");
		return -1;
	}
	return 0;
}

int display_avtab(avtab_t * a, uint32_t what, policydb_t * p, FILE * fp)
{
	int i;
	avtab_ptr_t cur;
	avtab_t expa;

	if (avtab_init(&expa))
		goto oom;
	if (expand_avtab(p, a, &expa)) {
		avtab_destroy(&expa);
		goto oom;
	}

	/* hmm...should have used avtab_map. */
	for (i = 0; i < AVTAB_SIZE; i++) {
		for (cur = expa.htable[i]; cur; cur = cur->next) {
			render_av_rule(&cur->key, &cur->datum, what, p, fp);
		}
	}
	avtab_destroy(&expa);
	fprintf(fp, "\n");
	return 0;
      oom:
	fprintf(stderr, "out of memory\n");
	return 1;
}

int display_bools(policydb_t * p, FILE * fp)
{
	int i;

	for (i = 0; i < p->p_bools.nprim; i++) {
		fprintf(fp, "%s : %d\n", p->p_bool_val_to_name[i],
			p->bool_val_to_struct[i]->state);
	}
	return 0;
}

void display_expr(policydb_t * p, cond_expr_t * exp, FILE * fp)
{

	cond_expr_t *cur;
	for (cur = exp; cur != NULL; cur = cur->next) {
		switch (cur->expr_type) {
		case COND_BOOL:
			fprintf(fp, "%s ",
				p->p_bool_val_to_name[cur->bool - 1]);
			break;
		case COND_NOT:
			fprintf(fp, "! ");
			break;
		case COND_OR:
			fprintf(fp, "|| ");
			break;
		case COND_AND:
			fprintf(fp, "&& ");
			break;
		case COND_XOR:
			fprintf(fp, "^ ");
			break;
		case COND_EQ:
			fprintf(fp, "== ");
			break;
		case COND_NEQ:
			fprintf(fp, "!= ");
			break;
		default:
			fprintf(fp, "error!");
			break;
		}
	}
}

int display_cond_expressions(policydb_t * p, FILE * fp)
{
	cond_node_t *cur;
	cond_av_list_t *av_cur, *expl = NULL;
	avtab_t expa;

	for (cur = p->cond_list; cur != NULL; cur = cur->next) {
		fprintf(fp, "expression: ");
		display_expr(p, cur->expr, fp);
		fprintf(fp, "current state: %d\n", cur->cur_state);
		fprintf(fp, "True list:\n");
		if (avtab_init(&expa))
			goto oom;
		if (expand_cond_av_list(p, cur->true_list, &expl, &expa)) {
			avtab_destroy(&expa);
			goto oom;
		}
		for (av_cur = expl; av_cur != NULL; av_cur = av_cur->next) {
			fprintf(fp, "\t");
			render_av_rule(&av_cur->node->key, &av_cur->node->datum,
				       RENDER_CONDITIONAL, p, fp);
		}
		cond_av_list_destroy(expl);
		avtab_destroy(&expa);
		fprintf(fp, "False list:\n");
		if (avtab_init(&expa))
			goto oom;
		if (expand_cond_av_list(p, cur->false_list, &expl, &expa)) {
			avtab_destroy(&expa);
			goto oom;
		}
		for (av_cur = expl; av_cur != NULL; av_cur = av_cur->next) {
			fprintf(fp, "\t");
			render_av_rule(&av_cur->node->key, &av_cur->node->datum,
				       RENDER_CONDITIONAL, p, fp);
		}
		cond_av_list_destroy(expl);
		avtab_destroy(&expa);
	}
	return 0;

      oom:
	fprintf(stderr, "out of memory\n");
	return 1;
}

int change_bool(char *name, int state, policydb_t * p, FILE * fp)
{
	cond_bool_datum_t *bool;

	bool = hashtab_search(p->p_bools.table, name);
	if (bool == NULL) {
		fprintf(fp, "Could not find bool %s\n", name);
		return -1;
	}
	bool->state = state;
	evaluate_conds(p);
	return 0;
}

int menu()
{
	printf("\nSelect a command:\n");
	printf("1)  display unconditional AVTAB\n");
	printf("2)  display conditional AVTAB (entirely)\n");
	printf("3)  display conditional AVTAG (only ENABLED rules)\n");
	printf("4)  display conditional AVTAB (only DISABLED rules)\n");
	printf("5)  display conditional bools\n");
	printf("6)  display conditional expressions\n");
	printf("7)  change a boolean value\n");
	printf("\n");
	printf("f)  set output file\n");
	printf("m)  display menu\n");
	printf("q)  quit\n");
	return 0;
}

int main(int argc, char **argv)
{
	FILE *out_fp = stdout;
	char ans[81], OutfileName[121];
	int fd, ret;
	struct stat sb;
	void *map;
	char *name;
	int state;
	struct policy_file pf;

	if (argc != 2)
		usage(argv[0]);

	fd = open(argv[1], O_RDONLY);
	if (fd < 0) {
		fprintf(stderr, "Can't open '%s':  %s\n",
			argv[1], strerror(errno));
		exit(1);
	}
	if (fstat(fd, &sb) < 0) {
		fprintf(stderr, "Can't stat '%s':  %s\n",
			argv[1], strerror(errno));
		exit(1);
	}
	map =
	    mmap(NULL, sb.st_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
	if (map == MAP_FAILED) {
		fprintf(stderr, "Can't map '%s':  %s\n",
			argv[1], strerror(errno));
		exit(1);
	}

	/* read the binary policy */
	fprintf(out_fp, "Reading policy...\n");
	pf.type = PF_USE_MEMORY;
	pf.data = map;
	pf.len = sb.st_size;
	if (policydb_init(&policydb)) {
		fprintf(stderr, "%s:  Out of memory!\n", argv[0]);
		exit(1);
	}
	ret = policydb_read(&policydb, &pf, 1);
	if (ret) {
		fprintf(stderr,
			"%s:  error(s) encountered while parsing configuration\n",
			argv[0]);
		exit(1);
	}

	fprintf(stdout, "binary policy file loaded\n\n");
	close(fd);

	menu();
	for (;;) {
		printf("\nCommand (\'m\' for menu):  ");
		fgets(ans, sizeof(ans), stdin);
		switch (ans[0]) {

		case '1':
			display_avtab(&policydb.te_avtab, RENDER_UNCONDITIONAL,
				      &policydb, out_fp);
			break;
		case '2':
			display_avtab(&policydb.te_cond_avtab,
				      RENDER_CONDITIONAL, &policydb, out_fp);
			break;
		case '3':
			display_avtab(&policydb.te_cond_avtab, RENDER_ENABLED,
				      &policydb, out_fp);
			break;
		case '4':
			display_avtab(&policydb.te_cond_avtab, RENDER_DISABLED,
				      &policydb, out_fp);
			break;
		case '5':
			display_bools(&policydb, out_fp);
			break;
		case '6':
			display_cond_expressions(&policydb, out_fp);
			break;
		case '7':
			printf("name? ");
			fgets(ans, sizeof(ans), stdin);
			ans[strlen(ans) - 1] = 0;

			name = malloc((strlen(ans) + 1) * sizeof(char));
			if (name == NULL) {
				fprintf(stderr, "couldn't malloc string.\n");
				break;
			}
			strcpy(name, ans);

			printf("state? ");
			fgets(ans, sizeof(ans), stdin);
			ans[strlen(ans) - 1] = 0;

			if (atoi(ans))
				state = 1;
			else
				state = 0;

			change_bool(name, state, &policydb, out_fp);
			free(name);
			break;
		case 'f':
			printf
			    ("\nFilename for output (<CR> for screen output): ");
			fgets(OutfileName, sizeof(OutfileName), stdin);
			OutfileName[strlen(OutfileName) - 1] = '\0';	/* fix_string (remove LF) */
			if (strlen(OutfileName) == 0)
				out_fp = stdout;
			else if ((out_fp = fopen(OutfileName, "w")) == NULL) {
				fprintf(stderr, "Cannot open output file %s\n",
					OutfileName);
				out_fp = stdout;
			}
			if (out_fp != stdout)
				printf("\nOutput to file: %s\n", OutfileName);
			break;
		case 'q':
			policydb_destroy(&policydb);
			exit(0);
			break;
		case 'm':
			menu();
			break;
		default:
			printf("\nInvalid choice\n");
			menu();
			break;

		}
	}
}

/* FLASK */
