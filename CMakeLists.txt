cmake_minimum_required(VERSION 3.30)
project(cryptoki-tool)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_C_STANDARD 99)

add_compile_definitions(_GNU_SOURCE)

set(CMAKE_EXE_LINKER_FLAGS "-fPIC -fpic") # -static
set(CMAKE_C_FLAGS "-fvisibility=hidden") # -pedantic
set(CMAKE_CXX_FLAGS "-fvisibility=hidden") # -pedantic

#link_directories(/usr/local/lib/softhsm/)
#link_directories(./feitian/)

add_executable(cryptoki-tool pkcs11-util.c pkcs11-client.c main.c)

#target_link_libraries(cryptoki-tool libsofthsm2.a)
#target_link_libraries(cryptoki-tool softhsm2)
#target_link_libraries(cryptoki-tool shuttle_p11v220)
#target_link_libraries(cryptoki-tool RastinPKCS11)
target_link_libraries(cryptoki-tool dl rt c)

