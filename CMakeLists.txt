cmake_minimum_required(VERSION 3.20)
set(CMAKE_TOOLCHAIN_FILE "${CMAKE_CURRENT_LIST_DIR}/../flipperzero-firmware/toolchain/x86_64-windows.cmake")
project(omega_ploutus_app)

add_subdirectory("${CMAKE_CURRENT_LIST_DIR}/../flipperzero-firmware" flipperzero-firmware)

add_flipperzero_app(omega_ploutus_app
    SOURCES omega_ploutus_app.c
    APP_MANIFEST application.fam
)
