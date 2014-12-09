broyara
=======

integrating bro into yara

I assume yara as been installed into `/usr/local/lib/`.

From the default bro source code (git cloned) add the following to `src/file_analysis/CMakeLists.txt`

```
add_subdirectory(data_event)
add_subdirectory(extract)
add_subdirectory(hash)
add_subdirectory(yara)
add_subdirectory(unified2)
add_subdirectory(x509)
```

I've also amended src/CMakeLists file

```
if ( bro_HAVE_OBJECT_LIBRARIES )
    add_executable(bro ${bro_SRCS} ${bro_HEADERS} ${bro_SUBDIRS})
    target_link_libraries(bro ${brodeps} ${CMAKE_THREAD_LIBS_INIT} ${CMAKE_DL_LIBS} yara)
else ()
    add_executable(bro ${bro_SRCS} ${bro_HEADERS})
    target_link_libraries(bro ${bro_SUBDIRS} ${brodeps} ${CMAKE_THREAD_LIBS_INIT} ${CMAKE_DL_LIBS} yara)
endif ()
```
You can run the yara rule analyser with a bro file like such:
```
redef record Files::AnalyzerArgs += 
	{
	yara_rules_file: string &optional;
	};

event file_new(f: fa_file)
    {
        Files::add_analyzer(f, Files::ANALYZER_YARA,[$yara_rules_file="/Users/jameshook/dev/src/bro/test.rule_c"]);
    }



event file_yaraalert(f: fa_file, rule_name: string)
	{
		print "file_yara_alert ", f$id," ",  rule_name;
	}

```
gives the output:
```
$ bro -r ~/data/pcap/intel.pcap broscipts/yara_tst.bro 
file_yara_alert , FqIk1M1mN4bdnsNK46,  , silent_banker
file_yara_alert , FxxvP43nXcYzL16gS6,  , silent_banker
file_yara_alert , FhKaLp4VGYlFgz0cj,  , silent_banker
file_yara_alert , FYWSmEkdLooAtsOd9,  , silent_banker
file_yara_alert , FC58QqHDkh3Z5ZCw,  , silent_banker
file_yara_alert , FFoGa51pLHJCHF68B,  , silent_banker
file_yara_alert , FfArYal4ANngQl0de,  , silent_banker
file_yara_alert , FGyLsu3kMoquT6RZda,  , silent_banker
1417869923.470556 warning in /usr/local/bro/share/bro/base/misc/find-checksum-offloading.bro, line 54: Your trace file likely has invalid TCP checksums, most likely from NIC checksum offloading.
file_yara_alert , F2PvdW1d2ZwYk6B0q9,  , silent_banker
file_yara_alert , FDWZJXmIc88eUN91i,  , silent_banker
file_yara_alert , F2PvdW1d2ZwYk6B0q9,  , silent_banker
file_yara_alert , FtULZK1hRBg008up1f,  , silent_banker
file_yara_alert , FJX6Dk435K8Xe05kp5,  , silent_banker
```



