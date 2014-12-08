// See the file "COPYING" in the main distribution directory for copyright.

#include <string>
#include <iostream>

#include "broyara.h"
#include "util.h"
#include "Event.h"
#include "file_analysis/Manager.h"

using namespace file_analysis;


int callback_function(
    int message,
    void* message_data,
    void* user_data)	{

	if (0 == user_data)	{
		return 1;
	}

	Yara* yara_callback_obj = static_cast<Yara*>(user_data);


	if (CALLBACK_MSG_RULE_MATCHING == message)	{
		yara_callback_obj->raiseEvent("RULE MATCH"); 
	} else if (CALLBACK_MSG_RULE_NOT_MATCHING == message)	{
		yara_callback_obj->raiseEvent("RULE NOT MATCH"); 
	} else if (CALLBACK_MSG_SCAN_FINISHED == message)	{
		yara_callback_obj->raiseEvent("RULE SCAN FINISHED"); 
	} else if (CALLBACK_MSG_IMPORT_MODULE == message)	{
		yara_callback_obj->raiseEvent("RULE IMPORT MODULE"); 
	} else {
		yara_callback_obj->raiseEvent("*** WHAT?!!?!!?? ***"); 
	}

	return ERROR_SUCCESS; // what are you meant to return from a callback function??

}

Yara::Yara(RecordVal* args, File* file, const char* arg_kind)
	: file_analysis::Analyzer(
		file_mgr->GetComponentTag(to_upper(arg_kind).c_str()), 
		args, 
		file), 
		fed(false),
		yr_rules_(0)
	{
		if (ERROR_SUCCESS != yr_initialize())	{
			throw "unable to initialize yara";
		}
		
		// const u_char* str1 = args->Lookup(0)->AsStringVal()->Bytes();
		// const u_char* str2 = args->Lookup(1)->AsStringVal()->Bytes();

		// std::cout << "\n1=" << str1 << std::endl;
		// std::cout << "\n2=" << str2 << std::endl;

		
		const char* rules_file_name = "/Users/jameshook/dev/src/bro/test.rule_c";

		if (ERROR_SUCCESS != yr_rules_load(rules_file_name,&yr_rules_))	{
			throw "unable to load yara rules";
		}


	}

Yara::~Yara()
	{
		if (0 != yr_rules_)	{
			yr_rules_destroy(yr_rules_);
		}
		yr_finalize();
	}

bool Yara::DeliverStream(const u_char* data, uint64 len)
	{
	ostream_.write((const char *) data,len);
	return true;
	}

bool Yara::EndOfFile()
	{
	Finalize();
	}

bool Yara::Undelivered(uint64 offset, uint64 len)
	{
	return false;
	}

void Yara::Finalize()
	{

		if (!ostream_)	{
			return;
		}

		std::string result_file = ostream_.str();

		if (0 == result_file.size())	{
			return;
		}


		//std::cout << "\nFileSize=" << result_file.size() << std::endl;


		int res = yr_rules_scan_mem(
			yr_rules_,
			(uint8_t *) result_file.c_str(),
			result_file.size(),
			SCAN_FLAGS_FAST_MODE,
			callback_function,
			this,
			0	// flags
			);

		if (ERROR_SUCCESS != res)	{
			//TODO: bro event??
			return;
		}


	}


void Yara::raiseEvent(const char* messageText)	{


	if (0 != file_yaraalert)	{

		val_list* vl = new val_list();
		vl->append(GetFile()->GetVal()->Ref());
		vl->append(new StringVal(messageText));
		mgr.QueueEvent(file_yaraalert, vl);

	}

	std::cout << messageText << std::endl;


}

