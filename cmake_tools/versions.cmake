
find_package (Git)
if (GIT_FOUND)
      message(STATUS "git found: ${GIT_EXECUTABLE} in version ${GIT_VERSION_STRING}")
endif (GIT_FOUND)

set (SW_MIKEY_SAKKE_DIR ${PROJECT_SOURCE_DIR} CACHE FILEPATH "path of sw_mikey_sakke")
message (STATUS "SW_MIKEY_SAKKE_DIR = ${SW_MIKEY_SAKKE_DIR}")

EXECUTE_PROCESS(WORKING_DIRECTORY ${SW_MIKEY_SAKKE_DIR} COMMAND ${GIT_EXECUTABLE} rev-parse --abbrev-ref HEAD OUTPUT_VARIABLE CURRENT_BRANCH)
EXECUTE_PROCESS(WORKING_DIRECTORY ${SW_MIKEY_SAKKE_DIR} COMMAND ${GIT_EXECUTABLE} describe --tags --abbrev=0 OUTPUT_VARIABLE CURRENT_TAG)

string(STRIP ${CURRENT_BRANCH} CURRENT_BRANCH)
string(STRIP ${CURRENT_TAG} CURRENT_TAG)

string(REPLACE "." ";" VERSION_LIST ${CURRENT_TAG})
list(GET VERSION_LIST 0 CURRENT_TAG_MAJOR)
list(GET VERSION_LIST 1 CURRENT_TAG_MINOR)
list(GET VERSION_LIST 2 CURRENT_TAG_REVISION)

message(STATUS "git branch: '${CURRENT_BRANCH}' / tag: '${CURRENT_TAG}' / rev: ${CURRENT_TAG_REVISION}")

if (${CURRENT_BRANCH} STREQUAL "master")
    target_compile_definitions(
        ${PROJECT_NAME}
        PUBLIC
        SW_MIKEY_SAKKE_VERSION="9999"
    )
else ()
    target_compile_definitions(
        ${PROJECT_NAME}
        PUBLIC
        SW_MIKEY_SAKKE_VERSION="${CURRENT_BRANCH}"
    )
endif (${CURRENT_BRANCH} STREQUAL "master")

target_compile_definitions(
    ${PROJECT_NAME}
    PUBLIC
    SW_MIKEY_SAKKE_REVISION="${CURRENT_TAG_REVISION}"
)