cmake_minimum_required(VERSION 4.1)
project(EChat LANGUAGES C)

# SERVER
add_executable(server
    tests/test_server.c
    #src/server.c
    include/MySocket.h
)

target_include_directories(server
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
)

# CLIENT
add_executable(client
    tests/test_client.c
    #src/client.c
    src/MsgEncrypt.c
    include/MsgEncrypt.h
)

target_include_directories(client
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${CMAKE_CURRENT_SOURCE_DIR}/OpenSSL/include
)

# OpenSSL
if(WIN32)
target_link_directories(server PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/OpenSSL/lib/VC/x64/MD)
target_link_directories(client PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/OpenSSL/lib/VC/x64/MD)

target_link_libraries(server PRIVATE ws2_32 libssl.lib libcrypto.lib)
target_link_libraries(client PRIVATE ws2_32 libcrypto.lib)
endif()

#find_package(OpenSSL REQUIRED)

#target_link_libraries(server PRIVATE
#    ws2_32
#    OpenSSL::SSL
#    OpenSSL::Crypto
#)

#target_link_libraries(client PRIVATE
#    ws2_32
#    OpenSSL::Crypto
#)

