find_package(Catch2 REQUIRED)
find_package(Botan3)

include(Catch)

add_executable(oosign_test main.cpp)

target_link_libraries(oosign_test
	Catch2::Catch2
	Botan3::Botan3
	oosign
)

catch_discover_tests(oosign_test)