/*******************************************************************************
 * Copyright (c) 2017, Ole Nissen.
 *  All rights reserved. 
 *  
 *  Redistribution and use in source and binary forms, with or without 
 *  modification, are permitted provided that the following conditions 
 *  are met: 
 *  1. Redistributions of source code must retain the above copyright 
 *  notice, this list of conditions and the following disclaimer. 
 *  2. Redistributions in binary form must reproduce the above
 *  copyright notice, this list of conditions and the following
 *  disclaimer in the documentation and/or other materials provided
 *  with the distribution. 
 *  3. The name of the author may not be used to endorse or promote
 *  products derived from this software without specific prior
 *  written permission.  
 *  
 *  THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS
 *  OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 *  WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 *  ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 *  DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 *  DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
 *  GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 *  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 *  WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 *  NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 *  SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.  
 *
 * This file is part of the Sensors Unleashed project
 *******************************************************************************/
/*
 * res-systeminfo.c
 *
 *  Created on: 07/10/2016
 *      Author: omn
 */
#define LOG6LBR_MODULE "SUROOT"

#include <string.h>
#include "contiki.h"
#include "rest-engine.h"
#include "dev/leds.h"
#include "er-coap-observe.h"
#include "er-coap-observe-client.h"
#include "node-info.h"

#include "cmp.h"

#include "log-6lbr.h"

#include <stdio.h>
#include <string.h>

#define CHECK_INTERVAL	CLOCK_SECOND * 10
static void res_sysinfo_gethandler(void *request, void *response, uint8_t *buffer, uint16_t preferred_size, int32_t *offset);
static void res_sysinfo_eventhandler(void);

resource_t res_sysinfo = {
		NULL,
		NULL,
		HAS_SUB_RESOURCES | IS_OBSERVABLE,
		"title=\"RootInfo\"",
		res_sysinfo_gethandler,
		NULL,
		NULL,
		NULL,
		{ .trigger = res_sysinfo_eventhandler }
};

static uint8_t nodeslistbuf[16*UIP_DS6_ROUTE_NB*3];
static uint8_t* nodeslistbuf_end = &nodeslistbuf[0];

static uint8_t nodeschangedbuf[16*UIP_DS6_ROUTE_NB*3];
static uint8_t* nodeschangedbuf_end = &nodeschangedbuf[0];

static bool buf_reader(cmp_ctx_t *ctx, void *data, uint32_t limit) {
	for(uint32_t i=0; i<limit; i++){
		*((char*)data++) = *((char*)ctx->buf++);
	}
	return true;
}


static uint32_t buf_writer(cmp_ctx_t* ctx, const void *data, uint32_t count){
	for(uint32_t i=0; i<count; i++){
		*((uint8_t*)ctx->buf++) = *((char*)data++);
	}
	return count;
}

void prepareNodeslist(){

	cmp_ctx_t cmp;
	cmp_init(&cmp, &nodeslistbuf[0], buf_reader, buf_writer);
	int count = 0;

	for(int i = 0; i < UIP_DS6_ROUTE_NB; i++) {
		if(node_info_table[i].isused) {
			count++;
			cmp_write_array(&cmp, sizeof(node_info_table[i].ipaddr));
			for(int j=0; j<sizeof(node_info_table[i].ipaddr); j++){
				cmp_write_u8(&cmp, node_info_table[i].ipaddr.u8[j]);
			}
			cmp_write_u32(&cmp, (uint32_t)((clock_time() - node_info_table[i].last_seen)/1000.0));
			cmp_write_u32(&cmp, node_info_table[i].flags);
		}
	}
	nodeslistbuf_end = cmp.buf;

	LOG6LBR_INFO("Found %d attached nodes\n", count);
}
/* Return number of changed nodes */
int prepareNodeChangedlist(){
	cmp_ctx_t cmp;
	cmp_init(&cmp, &nodeschangedbuf[0], buf_reader, buf_writer);
	int count = 0;

	for(int i = 0; i < UIP_DS6_ROUTE_NB; i++) {

		if(node_info_table[i].isused){
			if((clock_time() - node_info_table[i].last_seen) <= CHECK_INTERVAL) {
				count++;
				cmp_write_array(&cmp, sizeof(node_info_table[i].ipaddr));
				for(int j=0; j<sizeof(node_info_table[i].ipaddr); j++){
					cmp_write_u8(&cmp, node_info_table[i].ipaddr.u8[j]);
				}
				cmp_write_u32(&cmp, (uint32_t)((clock_time() - node_info_table[i].last_seen)/1000.0));
				cmp_write_u32(&cmp, node_info_table[i].flags);
			}
		}
	}

	if(count){
		nodeschangedbuf_end = cmp.buf;
		LOG6LBR_INFO("Found %d new node(s)\n", count);
	}

	return count;
}

static int fillBuffer(uint8_t *txbufptr, uint8_t *txbufptr_end, uint8_t *buffer, uint16_t preferred_size, int32_t *offset){
	int len = txbufptr_end - ((*offset) + txbufptr);
	len = len > preferred_size ? preferred_size : len;

	memcpy(buffer, txbufptr + *offset, len);

	//Use blockwise transfer, only if we need to.
	if( (txbufptr_end - txbufptr) > preferred_size ){
		if( len < preferred_size){	//This is the last message
			*offset = -1;
		}
		else{
			*offset += len;
		}
	}

	return len;
}

static void handle_subres(void *request, void *response, uint8_t *buffer, uint16_t preferred_size, int32_t *offset){

	const char *url = NULL;
	int len = REST.get_url(request, &url);
	int org_len = strlen(res_sysinfo.url);

	len = len - org_len;
	url = url + org_len;

	if(strncmp(url, "/change", len) == 0){
		len = fillBuffer(nodeschangedbuf, nodeschangedbuf_end, buffer, preferred_size, offset);
		REST.set_response_payload(response, buffer, len);
	}
}

static void
res_sysinfo_gethandler(void *request, void *response, uint8_t *buffer, uint16_t preferred_size, int32_t *offset){

	const char *url = NULL;
	const char *str = NULL;

	int url_len = strlen(res_sysinfo.url);
	int len = REST.get_url(request, &url);

	if((url_len == len && strncmp(url, res_sysinfo.url, url_len) == 0)){
		//This is a regular request - no sub resource
		len = REST.get_query(request, &str);
		if(len > 0){
			if(strncmp(str, "nodes", len) == 0){
				if(*offset == 0){
					prepareNodeslist();
				}
				len = fillBuffer(nodeslistbuf, nodeslistbuf_end, buffer, preferred_size, offset);
				REST.set_response_payload(response, buffer, len);
			}
			else{
				REST.set_response_status(response, REST.status.BAD_REQUEST);
			}
		}
		else{
			REST.set_response_status(response, REST.status.BAD_REQUEST);
		}
	}
	else if(((len > url_len) && (res_sysinfo.flags & HAS_SUB_RESOURCES) && (url[url_len] == '/'))
			&& strncmp(url, res_sysinfo.url, url_len) == 0) {
		handle_subres(request, response, buffer, preferred_size, offset);
	}
	else{
		REST.set_response_status(response, REST.status.NOT_FOUND);

	}
}

/* At regular interval, go through the list of nodes to find if any new has arrived */
static void res_sysinfo_eventhandler(void){

	if(prepareNodeChangedlist()){
		/* Notify the registered observers which will trigger the res_get_handler to create the response. */
		coap_notify_observers_sub(&res_sysinfo, "/change");
	}
}


PROCESS(su_node_monitor, "Sensors Unleashed root nodes monitor");
PROCESS_THREAD(su_node_monitor, ev, data)
{
	static struct etimer et;
	PROCESS_BEGIN();

	while(1) {
		etimer_set(&et, CLOCK_SECOND * 10);
		PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&et));
		res_sysinfo.trigger();
	}

	PROCESS_END();
}
