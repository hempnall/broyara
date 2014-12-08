// See the file  in the main distribution directory for copyright.

#include "plugin/Plugin.h"
#include <iostream>
#include "broyara.h"

namespace plugin {
namespace Bro_FileYara {

class Plugin : public plugin::Plugin {
public:
	plugin::Configuration Configure()
		{

		AddComponent(new ::file_analysis::Component("YARA", ::file_analysis::Yara::Instantiate));
		plugin::Configuration config;
		config.name = "Bro::FileYara";
		config.description = "Yara file content scanner";	
		return config;


		}

} plugin;

}
}
