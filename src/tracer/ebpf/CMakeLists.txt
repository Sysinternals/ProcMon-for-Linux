
target_sources(tracer-static PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/ebpf_tracer_engine.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/raw_ebpf_event.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/syscall_schema.cpp"
)