cmake_minimum_required(VERSION 3.30)
project(cryptoki_test)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_C_STANDARD 99)

add_compile_definitions(_GNU_SOURCE)

#set(CMAKE_EXE_LINKER_FLAGS "-static -fPIC -fpic")
set(CMAKE_C_FLAGS "-fvisibility=hidden") # -pedantic
set(CMAKE_CXX_FLAGS "-fvisibility=hidden") # -pedantic

#link_directories(/usr/local/lib/softhsm/)
#link_directories(./feitian/)

add_executable(cryptoki_test pkcs11-impl.c main.c)

#target_link_libraries(cryptoki_test libsofthsm2.a)
#target_link_libraries(cryptoki_test softhsm2)
#target_link_libraries(cryptoki_test shuttle_p11v220)
target_link_libraries(cryptoki_test dl rt)

