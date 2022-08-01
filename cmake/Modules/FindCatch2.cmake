include(FetchContent)

option(
	INSTALL_CATCH2
	"Enable installation of catch2"
	OFF
)

message(STATUS "Downloading Catch2 library")

FetchContent_Declare(
	Catch2
	GIT_REPOSITORY https://github.com/catchorg/Catch2.git
	GIT_TAG        v2.13.9
)

FetchContent_MakeAvailable(Catch2)

list(APPEND CMAKE_MODULE_PATH ${Catch2_SOURCE_DIR}/contrib)