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




