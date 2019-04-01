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



DWORD test(Remote *remote, Packet *packet)
{
	
	

	dprintf("TIMOTIMOTIMO testCommandStart");
	Packet *response = packet_create_response(packet);
	int result = ERROR_SUCCESS;
	dprintf("TIMOTIMOTIMO adding string to response");
	packet_add_tlv_string(response, TLV_TYPE_MALLEABLE_INTERFACES, "It works!"); 
	packet_transmit_response(result, remote, response);
	
	dprintf("TIMOTIMOTIMO testCommandEnd");
	return ERROR_SUCCESS;
}