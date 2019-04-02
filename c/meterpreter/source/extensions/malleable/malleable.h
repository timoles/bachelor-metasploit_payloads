/*!
 * @file malleable.h
 * @brief Entry point and intialisation declrations for the malleable extention.
 */
#ifndef _METERPRETER_SOURCE_EXTENSION_MALLEABLE_MALLEABLE_H
#define _METERPRETER_SOURCE_EXTENSION_MALLEABLE_MALLEABLE_H

#define luac_c
#define LUA_CORE

#include "lua-5.3.5\src\lprefix.h"
#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "lua-5.3.5\src\lua.h"
#include "lua-5.3.5\src\lauxlib.h"
#include "lua-5.3.5\src\lobject.h"
#include "lua-5.3.5\src\lstate.h"
#include "lua-5.3.5\src\lundump.h"
#include "lua-5.3.5\src\lualib.h"

#include "../../common/common.h"

// Custom TLVs go here
#define TLV_TYPE_EXTENSION_MALLEABLE	0


#define TLV_TYPE_MALLEABLE_INTERFACES	\
		MAKE_CUSTOM_TLV(							\
				TLV_META_TYPE_STRING,				\
				TLV_TYPE_EXTENSION_MALLEABLE,		\
				TLV_EXTENSIONS + 1)

#endif
