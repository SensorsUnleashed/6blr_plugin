/*
 * res-detect.c
 *
 *  Created on: 5. dec. 2017
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

#define CHECK_INTERVAL	CLOCK_SECOND * 30

static void res_detect_gethandler(void *request, void *response, uint8_t *buffer, uint16_t preferred_size, int32_t *offset);
static void res_detect_eventhandler(void);

PROCESS(su_detector, "Sensors Unleashed detector");

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

resource_t res_detect = {
		NULL,
		NULL,
		IS_OBSERVABLE,
		"title=\"detecter\"",
		res_detect_gethandler,
		NULL,
		NULL,
		NULL,
		{ .trigger = res_detect_eventhandler }
};

struct detecters_s {
	struct detecters_s *next;   /* for LIST */
	uip_ipaddr_t ipaddr;
	char query[COAP_OBSERVER_QUERY_LEN];
	int first;	//First time is active discovery of the node
};
typedef struct detecters_s detecters_t;

MEMB(detectors_memb, detecters_t, COAP_MAX_OBSERVERS);
LIST(detectors_list);

//When a device is found, txlen will be > 0
int txlen = 0;
uint8_t txbuffer[32];


static void res_detect_gethandler(void *request, void *response, uint8_t *buffer, uint16_t preferred_size, int32_t *offset){

	const char *query = NULL;

	int len = REST.get_query(request, &query);
	LOG6LBR_INFO("res_detect_gethandler txlen=%d\n", txlen);

	if(len > 0){
		if(txlen){	//If this flag is set, we know its a notification message, and we have something to notify
			memcpy(buffer, txbuffer, txlen);
			REST.set_response_payload(response, buffer, txlen);
			REST.set_response_status(response, REST.status.OK);
		}
		else{	//Its a request to detect a node
			detecters_t *d = memb_alloc(&detectors_memb);
			if(d){
				//We need to add the '&' because thats the way to identify a query
				*d->query = '?';
				char* q = d->query + 1;
				memcpy(q, query, len);
				*(q+len+1) = '\0';
				if(uiplib_ip6addrconv(q, &d->ipaddr) == 0){
					memb_free(&detectors_memb, d);
					REST.set_response_status(response, REST.status.BAD_REQUEST);
					return;
				}

				d->first = 1;
				list_add(detectors_list, d);
				process_poll(&su_detector);
			}
			else{
				REST.set_response_status(response, REST.status.INTERNAL_SERVER_ERROR);
			}
		}
	}
	else{
		REST.set_response_status(response, REST.status.BAD_REQUEST);
	}
}


detecters_t* nodefound = 0;

static void nodeFoundhandler(void *data, void *response){
	if(response != 0){
		//We received something - means its ON. Notify the process
		nodefound = (detecters_t*) data;
		const uint8_t *data;
		LOG6LBR_INFO("nodeFoundhandler: %d\n", REST.get_request_payload(response, &data));
		process_poll(&su_detector);
	}
	else{
		LOG6LBR_INFO("nodeFoundhandler timeout\n");
	}
}

static void txNodeDiscovry(detecters_t* d){
	coap_packet_t request[1];
	coap_transaction_t *t;

	coap_init_message(request, COAP_TYPE_CON, COAP_GET, coap_get_mid());
	coap_set_header_uri_path(request, "su/nodeinfo/Versions");	//Any message will do, we only need to see it awake

	t = coap_new_transaction(request->mid, &d->ipaddr, UIP_HTONS(COAP_DEFAULT_PORT));
	if(t) {
		t->callback = nodeFoundhandler;
		t->callback_data = d;
		t->packet_len = coap_serialize_message(request, t->packet);
		coap_send_transaction(t);
	}
}

static void notify(detecters_t* d){
	cmp_ctx_t cmp;
	cmp_init(&cmp, txbuffer, buf_reader, buf_writer);
	//To keep it in one message, we pack the u16 version.
	//With u16 it takes 2*8+8+1 = 25bytes
	//With u8 it takes up 16*2+2 = 34bytes NO GO!
	cmp_write_array(&cmp, 8);
	for(int j=0; j<8; j++){
		cmp_write_u16(&cmp, d->ipaddr.u16[j]);
	}

	txlen = (int)((size_t)cmp.buf - (size_t)txbuffer);
	coap_notify_observers_sub(&res_detect, d->query);

	memb_free(&detectors_memb, d);
	list_remove(detectors_list, d);

	//We're done transmitting when we return (Or at least, things has been copied away)
	txlen = 0;
}

/* At regular interval, go through the list of nodes to find if any new has arrived */
static void res_detect_eventhandler(void){


	detecters_t* d = NULL;
	for(d = (detecters_t *)list_head(detectors_list); d; d = d->next) {
		if(d->first){
			//Try to contact the node, to see if it responds
			txNodeDiscovry(d);
			d->first = 0;
		}
		else{
			for(int i = 0; i < UIP_DS6_ROUTE_NB; i++) {
				if(node_info_table[i].isused){
					if(memcmp( d->ipaddr.u8, node_info_table[i].ipaddr.u8, 16 ) == 0){
						if((clock_time() - node_info_table[i].last_seen) <= CHECK_INTERVAL) {
							notify(d);
						}
					}
				}
			}
		}
	}
}

PROCESS_THREAD(su_detector, ev, data)
{
	static struct etimer et;
	PROCESS_BEGIN();

	while(1) {
		etimer_set(&et, CLOCK_SECOND * 10);
		PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&et) || nodefound != 0);
		if(nodefound){
			notify(nodefound);
			nodefound = 0;
		}
		else{
			res_detect.trigger();
		}
	}

	PROCESS_END();
}
