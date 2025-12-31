# IP Project
project(ip VERSION 0.0.1 LANGUAGES CXX)

# Create executable
add_executable(01-pcap src/main.cpp)

# Download and extract The-Ultimate-PCAP.7z
set(PCAP_URL "https://weberblog.net/wp-content/uploads/2020/02/The-Ultimate-PCAP.7z")
set(PCAP_ARCHIVE "${CMAKE_CURRENT_BINARY_DIR}/The-Ultimate-PCAP.7z")
set(PCAP_EXTRACT_DIR "${CMAKE_CURRENT_BINARY_DIR}/data")
set(PCAP_EXTRACT_MARKER "${CMAKE_CURRENT_BINARY_DIR}/.pcap_extracted")

# Find 7z executable (7z on Linux/Windows, 7zz on macOS via Homebrew)
find_program(SEVEN_ZIP_EXECUTABLE NAMES 7z 7zz 7za
    HINTS
        "C:/Program Files/7-Zip"
        "C:/Program Files (x86)/7-Zip"
        "$ENV{ProgramFiles}/7-Zip"
        "$ENV{ProgramFiles\(x86\)}/7-Zip"
)

if(NOT SEVEN_ZIP_EXECUTABLE)
    message(WARNING "7z not found. Please install p7zip (Linux) or 7zip (macOS: brew install 7zip) to extract PCAP files.")
else()
    # Download the archive if it doesn't exist
    if(NOT EXISTS "${PCAP_ARCHIVE}")
        message(STATUS "Downloading The-Ultimate-PCAP.7z...")
        file(DOWNLOAD
            "${PCAP_URL}"
            "${PCAP_ARCHIVE}"
            SHOW_PROGRESS
            STATUS DOWNLOAD_STATUS
        )
        list(GET DOWNLOAD_STATUS 0 DOWNLOAD_STATUS_CODE)
        if(NOT DOWNLOAD_STATUS_CODE EQUAL 0)
            message(WARNING "Failed to download The-Ultimate-PCAP.7z")
        endif()
    endif()

    # Extract the archive if not already extracted
    if(EXISTS "${PCAP_ARCHIVE}" AND NOT EXISTS "${PCAP_EXTRACT_MARKER}")
        message(STATUS "Extracting The-Ultimate-PCAP.7z...")
        file(MAKE_DIRECTORY "${PCAP_EXTRACT_DIR}")
        execute_process(
            COMMAND "${SEVEN_ZIP_EXECUTABLE}" x -y "${PCAP_ARCHIVE}" -o${PCAP_EXTRACT_DIR}
            RESULT_VARIABLE EXTRACT_RESULT
        )
        if(EXTRACT_RESULT EQUAL 0)
            file(TOUCH "${PCAP_EXTRACT_MARKER}")
            message(STATUS "Successfully extracted PCAP files to ${PCAP_EXTRACT_DIR}")
        else()
            message(WARNING "Failed to extract The-Ultimate-PCAP.7z")
        endif()
    endif()
endif()

# Set C++ standard (inherited from parent, but explicit here)
target_compile_features(01-pcap PRIVATE cxx_std_23)

# Link to PcapPlusPlus
target_link_libraries(01-pcap PRIVATE Pcap++ Packet++ Common++)

# Add compile options
if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang|AppleClang")
    target_compile_options(01-pcap PRIVATE -Wall -Wextra -Wpedantic)
endif()

# Install target
install(TARGETS 01-pcap DESTINATION bin)

# Copy PNG screenshots to binary directory for testing
set(SCREENSHOT_FILES
    repo_name.png
    actions_enabled.png
    collaborators.png
    ai_disabled.png
)

foreach(SCREENSHOT ${SCREENSHOT_FILES})
    if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/${SCREENSHOT}")
        configure_file(
            "${CMAKE_CURRENT_SOURCE_DIR}/${SCREENSHOT}"
            "${CMAKE_CURRENT_BINARY_DIR}/${SCREENSHOT}"
            COPYONLY
        )
    endif()
endforeach()

# Test executable
add_executable(01-pcap-tests tests/tests.cpp)
target_compile_features(01-pcap-tests PRIVATE cxx_std_23)
target_link_libraries(01-pcap-tests PRIVATE Pcap++ Packet++ Common++ doctest::doctest)

if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang|AppleClang")
    target_compile_options(01-pcap-tests PRIVATE -Wall -Wextra -Wpedantic)
endif()

# Set working directory for tests to find the data folder
set_target_properties(01-pcap-tests PROPERTIES
    VS_DEBUGGER_WORKING_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}"
)

# Add test to CTest
include(CTest)
add_test(NAME 01-pcap-tests
    COMMAND 01-pcap-tests
    WORKING_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}"
)

