add_executable(dm-verity-agent dm-verity-agent.cc)

find_library(crypto, crypto REQUIRED)
find_library(cryptsetup, cryptsetup REQUIRED)
find_library(tss2-esys, tss2-esys REQUIRED)

find_library(spdlog, spdlog REQUIRED)
add_definitions(-DSPDLOG_FMT_EXTERNAL)
find_library(fmt, fmt REQUIRED)

target_link_libraries(dm-verity-agent crypto tss2-esys cryptsetup fmt)

install(TARGETS dm-verity-agent
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)