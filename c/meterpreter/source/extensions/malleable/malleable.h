/*!
 * @file malleable.h
 * @brief Entry point and intialisation declrations for the malleable extention.
 */
#ifndef _METERPRETER_SOURCE_EXTENSION_MALLEABLE_MALLEABLE_H
#define _METERPRETER_SOURCE_EXTENSION_MALLEABLE_MALLEABLE_H



#include "../../common/common.h"


// Custom TLVs go here
#define TLV_TYPE_EXTENSION_MALLEABLE	0


#define TLV_TYPE_MALLEABLE_INTERFACES	\
		MAKE_CUSTOM_TLV(							\
				TLV_META_TYPE_STRING,				\
				TLV_TYPE_EXTENSION_MALLEABLE,		\
				TLV_EXTENSIONS + 1)

#endif
