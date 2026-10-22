cmake_minimum_required(VERSION 3.15)
project(vaultc LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Ajuste para a sua instalacao da libvault (https://github.com/abedra/libvault).
# Ex.: -DLIBVAULT_INCLUDE_DIR=C:/deps/libvault/include
#      -DLIBVAULT_LIBRARY=C:/deps/libvault/lib/vault.lib
set(LIBVAULT_INCLUDE_DIR "" CACHE PATH     "Diretorio que contem libvault/VaultClient.h")
set(LIBVAULT_LIBRARY     "" CACHE FILEPATH "Biblioteca libvault (.lib / .a)")

find_package(CURL REQUIRED)
find_package(nlohmann_json CONFIG REQUIRED)   # ou aponte para o json.hpp avulso

add_library(vaultc SHARED vaultc.cpp vaultc.h)
target_compile_definitions(vaultc PRIVATE VAULTC_BUILD_DLL)
target_include_directories(vaultc
    PRIVATE ${LIBVAULT_INCLUDE_DIR}
    PUBLIC  ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(vaultc PRIVATE
    ${LIBVAULT_LIBRARY}
    CURL::libcurl
    nlohmann_json::nlohmann_json)

# Opcional: runtime estatico, para a DLL nao exigir o redistribuivel do VC++.
# Seguro aqui porque nenhuma memoria cruza a fronteira (vault_free na DLL).
# set_property(TARGET vaultc PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

# Gera vaultc.dll + vaultc.lib (import library) em compiladores MSVC/clang-cl.
