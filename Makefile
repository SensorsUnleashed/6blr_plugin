6LBR_PLUGIN=su_root.so

6LBR=../..

PLUGIN_SOURCEFILES+=su_root.c res-systeminfo.c cmp.c res-detect.c

#APPS+=$(6LBR)/../6lbr-demo/apps/lwm2m

#PLUGIN_APPS+=lwm2m
#PLUGIN_PROJECT_CONF=lwm2m-client.h

include $(6LBR)/Makefile
