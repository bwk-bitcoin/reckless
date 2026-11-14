add_library(reckless_interfaces INTERFACE)

target_include_directories(reckless_interfaces
    INTERFACE
    ${CMAKE_CURRENT_SOURCE_DIR}/..
    $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/src>
)
