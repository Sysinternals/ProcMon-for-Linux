
add_library(tracer-static STATIC
    "${CMAKE_CURRENT_SOURCE_DIR}/mock_tracer_engine.cpp"
)

add_subdirectory(ebpf)