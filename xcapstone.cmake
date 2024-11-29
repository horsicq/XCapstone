include_directories(${CMAKE_CURRENT_LIST_DIR})
include_directories(${CMAKE_CURRENT_LIST_DIR}/3rdparty/Capstone/src/include/)

if (NOT DEFINED XBINARY_SOURCES)
    include(${CMAKE_CURRENT_LIST_DIR}/../Formats/xbinary.cmake)
    set(XCAPSTONE_SOURCES ${XCAPSTONE_SOURCES} ${XBINARY_SOURCES})
endif()

set(XCAPSTONE_SOURCES
    ${XCAPSTONE_SOURCES}
    ${XBINARY_SOURCES}
    ${CMAKE_CURRENT_LIST_DIR}/xcapstone.cpp
    ${CMAKE_CURRENT_LIST_DIR}/xcapstone.h
)
