
add_library(display-static STATIC
    "${CMAKE_CURRENT_SOURCE_DIR}/screen.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/column.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/event_formatter.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/kill_event_formatter.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/headless.cpp"
)