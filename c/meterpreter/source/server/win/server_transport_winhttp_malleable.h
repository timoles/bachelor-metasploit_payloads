#ifndef _METERPRETER_SERVER_TRANSPORT_WINHTTP_MALLEABLE
#define _METERPRETER_SERVER_TRANSPORT_WINHTTP_MALLEABLE

void transport_write_http_malleable_config(Transport* transport, MetsrvTransportHttp* config);
Transport* transport_create_http_malleable(MetsrvTransportHttp* httpConfig, LPDWORD size);

void transport_move_to_malleable(Transport* transport);

#endif