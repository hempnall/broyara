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




