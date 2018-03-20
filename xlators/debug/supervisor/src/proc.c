/*
 * This is sample code generated by rpcgen.
 * These are only templates and you can use them
 * as a guideline for developing your own functions.
 */


#include "msg.h"
#ifndef _CONFIG_H
#define _CONFIG_H
#include "config.h"
#endif
#include <time.h>
#include <errno.h>
#include "lwfs.h"
#include "xlator.h"
#include "common-utils.h"
#include "dict.h"

#ifndef GF_SWOS
extern xlator_t *sv_this;
#endif

extern void enable_call_id(const int, int);
extern int get_call_status_id(const int);

valuebuf *
getkeyvalue_2_svc(msgtype *argp, struct svc_req *rqstp)
{
	static valuebuf  result;

	/*
	 * insert server code here
	 */
	
	char *name = argp->m_xlator;
	char *key = argp->m_key;
	uint64_t	key_value;
	uint64_t value = argp->m_value;
	valuebuf vb;
	xlator_t *xl = NULL;
	int ret = 0;

	xl = xlator_search_by_name(sv_this,name);
	/*
	 * do something with this xl
	 */
	if ( xl == NULL ) {
		result.err = -ENOENT;
		return &result;
	}
#ifdef JJH
	if ( !strncmp("inode",argp->m_key,5) ){
		if(xl->dumpops->inode) {
	                ret = xl->dumpops->inode(xl);
			result.valuebuf_u.retbuf.m_value = key_value;
	        }
	        else {
	                gf_log(xl->name, GF_LOG_ERROR, "dumpops have no inode function");
	                return NULL;
	        }
		goto out;
	}

	if ( !strncmp("priv",argp->m_key,4) ){
		if(xl->dumpops->priv) {
	                ret = xl->dumpops->priv(xl);
			result.valuebuf_u.retbuf.m_value = key_value;
	        }
	        else {
	                gf_log(xl->name, GF_LOG_ERROR, "dumpops have no priv function");
	                return NULL;
	        }
		goto out;
	}

	if ( !strncmp("fd",argp->m_key,2) ){
		if(xl->dumpops->fd) {
	                ret = xl->dumpops->fd(xl);
			result.valuebuf_u.retbuf.m_value = key_value;
	        }
	        else {
	                gf_log(xl->name, GF_LOG_ERROR, "dumpops have no fd function");
	                return NULL;
	        }
		goto out;
	}

out:
#endif
        return &result;
}

int *
setkeyvalue_2_svc(msgtype *argp, struct svc_req *rqstp)
{
	static int  result;

	/*
	 * insert server code here
	 */

	return &result;
}

retbulkbuf *
getbulk_2_svc(mdtype *argp, struct svc_req *rqstp)
{
        static retbulkbuf  result;
	 xlator_t *xl;
	char name[16]="server";
	char *buf;
	int len;

        /*
         * insert server code here
         */
	result.err = 0;
	xl = xlator_search_by_name(sv_this, name);
	if(xl == NULL) {
		gf_log("proc", GF_LOG_ERROR, "find xlator by name error");
		return &result;
	}
        return &result;
}

retbulkbuf *
getxlinfo_2_svc(msgtype *argp, struct svc_req *rqstp)
{
        static retbulkbuf  result;
	 xlator_t *xl;
	char *name = argp->m_xlator;
	char *key = argp->m_key;
	char *buf;
	int len;

	result.err = 0;
        /*
         * insert server code here
         */
	xl = xlator_search_by_name(sv_this, name);
	if(xl == NULL) {
		gf_log("proc", GF_LOG_ERROR, "find xlator by name error");
		return &result;
	}
#ifdef HXB090227
	buf = xl->cops->getbulk(xl, NULL, NULL, &len, 0);
	if(buf != NULL) {
		strncpy(result.retbulkbuf_u.retbuf.b_bulk, buf, strlen(buf));
		result.retbulkbuf_u.retbuf.b_size = strlen(buf);
		free(buf);
        	return &result;
	}
	else
		gf_log(xl->name, GF_LOG_ERROR,  "getxlinfo return NULL\n");
#endif
        /*
         * insert server code here
         */

        return &result;
}

int *
getstatus_2_svc(void *argp, struct svc_req *rqstp)
{
	static int  result;

	/*
	 * insert server code here
	 */

	return &result;
}

int *
getdblevel_2_svc(void *argp, struct svc_req *rqstp)
{
	static int  result;

	/*
	 * insert server code here
	 */
        gf_loglevel_t gl= gf_log_get_loglevel();
        result = (int)gl;
        return &result;
}

int *
setdblevel_2_svc(int *argp, struct svc_req *rqstp)
{
	static int  result;

	/*
	 * insert server code here
	 */
	int *num = argp;
        result = -1;
        if((*num < GF_LOG_NONE) & (*num > GF_LOG_DEBUG))
                return(&result);
        result = 0;
        gf_log_set_loglevel (*num);
        return(&result);
}

int *
getopmask_2_svc(int *argp, struct svc_req *rqstp)
{
	static int  result;

	/*
	 * insert server code here
	 */
	int *num = argp;
        result = -1;
        if((*num == 0)&( *num > GF_FOP_MAXVALUE)) {
                gf_log("proc", GF_LOG_ERROR, 
			"lwfs get opmask failed: invalid argument[%d]\n", *num);
                return(&result);
        }
        result = get_call_status_id(*num);
        return(&result);
}

int *
setopmask_2_svc(int *argp, struct svc_req *rqstp)
{
	static int  result;

	/*
	 * insert server code here
	 */
	int *num = argp;
	int enabled = 0;
        if(*num > 0) 
                enabled = 1;
	else
                *num = - (*num);
        result = -1;
        if( *num > GF_FOP_MAXVALUE) {
                gf_log("proc", GF_LOG_ERROR, 
			"lwfs set opmask failed: invalid argument[%d]\n", *num);
                return(&result);
        }
        enable_call_id(*num, enabled);
        result = 0;
        return &result;
}

int *
resetjob_2_svc(int *argp, struct svc_req *rqstp)
{
	static int  result;

	/*
	 * insert server code here
	 */

	return &result;
}