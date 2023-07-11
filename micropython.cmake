# Create an INTERFACE library for our C module.
add_library(usermod_uaesgcm INTERFACE)

# Add our source files to the lib
target_sources(usermod_uaesgcm INTERFACE
${CMAKE_CURRENT_LIST_DIR}/AesGCM.c
${CMAKE_CURRENT_LIST_DIR}/modaesgcm.c
)

# Add the current directory as an include directory.
target_include_directories(usermod_uaesgcm INTERFACE
    ${CMAKE_CURRENT_LIST_DIR}
)

target_compile_definitions(usermod_uaesgcm INTERFACE
    MICROPY_PY_UAESGCM=1
)

# Link our INTERFACE library to the usermod target.
target_link_libraries(usermod INTERFACE usermod_uaesgcm)
