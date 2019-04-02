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

// this sets the delay load hook function, see DelayLoadMetSrv.h
EnableDelayLoadMetSrv();

DWORD test(Remote *remote, Packet *packet);


Command customCommands[] =
{
	COMMAND_REQ("malleable_test_command", test),
	COMMAND_TERMINATOR
};

/*!
 * @brief Initialize the server extension
 */
DWORD __declspec(dllexport) InitServerExtension(Remote *remote)
{
	dprintf("TIMOTIMOTIMO malleableInit");
	hMetSrv = remote->met_srv;

	command_register_all(customCommands);

	return ERROR_SUCCESS;
}

/*!
 * @brief Deinitialize the server extension
 */
DWORD __declspec(dllexport) DeinitServerExtension(Remote *remote)
{
	command_deregister_all(customCommands);

	return ERROR_SUCCESS;
}

void bail(lua_State *L, char *msg){
	dprintf("[TIMOTIMOTIMOMALLEABLE] FATAL ERROR:  %s: %s",
		msg, lua_tostring(L, -1));
}

DWORD test(Remote *remote, Packet *packet)
{
	dprintf("[TIMOTIMOTIMOMALLEABLE] testCommandStart");
	lua_State *L;

	L = luaL_newstate();                        /* Create Lua state variable */
	luaL_openlibs(L);                           /* Load Lua libraries */

	if (luaL_loadfile(L, "testFunction.lua")) /* Load but don't run the Lua script */
		bail(L, "luaL_loadfile() failed");      /* Error out if file can't be read */

	if (lua_pcall(L, 0, 0, 0))                  /* PRIMING RUN. FORGET THIS AND YOU'RE TOAST */
		bail(L, "lua_pcall() failed");          /* Error out if Lua file has an error */

	lua_getglobal(L, "encrypt");
	lua_pushstring(L, "evilMeterpreterData");
	if (lua_pcall(L, 1, 1, 0))
		bail(L, "lua_pcall() failed");
	const char *encryptedOut = lua_tostring(L, -1);
	dprintf("Sending out: %s\n", encryptedOut);

	Packet *response = packet_create_response(packet);
	int result = ERROR_SUCCESS;
	dprintf("[TIMOTIMOTIMOMALLEABLE] adding string to response");
	packet_add_tlv_string(response, TLV_TYPE_MALLEABLE_INTERFACES, "It works!"); 
	packet_transmit_response(result, remote, response);
	
	dprintf("[TIMOTIMOTIMOMALLEABLE] testCommandEnd");
	return ERROR_SUCCESS;
}