include_directories(${CMAKE_CURRENT_LIST_DIR})
include_directories(${CMAKE_CURRENT_LIST_DIR}/3rdparty/Capstone/src/include/)

include(${CMAKE_CURRENT_LIST_DIR}/../Formats/xbinary.cmake)

set(XCAPSTONE_SOURCES
    ${XBINARY_SOURCES}
    ${CMAKE_CURRENT_LIST_DIR}/xcapstone.cpp
    ${CMAKE_CURRENT_LIST_DIR}/xcapstone.h
)
