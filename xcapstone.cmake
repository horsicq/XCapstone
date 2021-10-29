# TODO guard
include_directories(${CMAKE_CURRENT_LIST_DIR})
include_directories(${CMAKE_CURRENT_LIST_DIR}/3rdparty/Capstone/src/include/)

set(XCAPSTONE_SOURCES
    ${CMAKE_CURRENT_LIST_DIR}/xcapstone.cpp
)
