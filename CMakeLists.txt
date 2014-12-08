include(BroPlugin)

include_directories(BEFORE ${CMAKE_CURRENT_SOURCE_DIR}
                           ${CMAKE_CURRENT_BINARY_DIR}
                           "/Users/jameshook/dev/src/yara-3.2.0/libyara/include"
                           )






bro_plugin_begin(Bro FileYara)
bro_plugin_cc(broyara.cc Plugin.cc ../../Analyzer.cc)
bro_plugin_bif(events.bif)
bro_plugin_end()
