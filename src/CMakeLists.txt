project(oosign)

find_package(Botan3 REQUIRED)

set(SOURCES
	Key.cpp
	Sign.cpp
	TrapdoorHash.cpp
)

set(HEADERS
	Key.hpp
	Sign.hpp
	TrapdoorHash.hpp
)

add_library(oosign ${SOURCES} ${HEADERS})

target_link_libraries(oosign
	PRIVATE
	Botan3::Botan3
)

target_include_directories(oosign PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})