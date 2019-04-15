#ifndef _METERPRETER_SERVER_TRANSPORT_WINHTTP_MALLEABLE
#define _METERPRETER_SERVER_TRANSPORT_WINHTTP_MALLEABLE

#define luac_c
#define LUA_CORE

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "lua-5.3.5\src\lprefix.h"
#include "lua-5.3.5\src\lua.h"
#include "lua-5.3.5\src\lauxlib.h"
#include "lua-5.3.5\src\lobject.h"
#include "lua-5.3.5\src\lstate.h"
#include "lua-5.3.5\src\lundump.h"
#include "lua-5.3.5\src\lualib.h"

static char * luaScript = "function encode(s);s = '<html> viewstate=\"' .. s ..  '\" </html>';return s;end;";

void transport_write_http_malleable_config(Transport* transport, MetsrvTransportHttp* config);
Transport* transport_create_http_malleable(MetsrvTransportHttp* httpConfig, LPDWORD size);

void transport_move_to_malleable(Transport* transport);

#endif