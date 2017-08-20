OPTION(GITTEST_COMMON_CONFIG_GENERATION_DISABLE "Use an empty default config instead of generating one" OFF)
SET(GITTEST_COMMON_CONFIG_GENERATION_FILEPATH "SETME" CACHE FILEPATH "(Path to) Config file used for generating")
SET(GITTEST_COMMON_PREFIX "SETME" CACHE PATH "Will be strategically prefixed to used paths")


FUNCTION (GITTEST_COMMON_SET_GENERATION)
  # define a config header generator executable target (GsCommonConfigHeaderGen).
  # unless GITTEST_DISABLE_CONFIG_GENERATION disables config generation,
  #   (in which case a bundled empty default header is used)
  # setup generation of the header from a config file, using the generator executable target.
  # The generated header will be output into CMAKE_BINARY_DIR as GsConfigHeader.h

  ADD_EXECUTABLE(GsCommonConfigHeaderGen
    ${GITTEST_COMMON_PREFIX}/src/gen/config_header_gen.cpp
  )
  
  IF (GITTEST_COMMON_CONFIG_GENERATION_DISABLE)
    ADD_CUSTOM_COMMAND(
      OUTPUT GsConfigHeader.h
      DEPENDS "${GITTEST_COMMON_PREFIX}/data/GsConfigHeaderDefault.h"
      COMMAND "${CMAKE_COMMAND}"
        -E copy
        "${GITTEST_COMMON_PREFIX}/data/GsConfigHeaderDefault.h"
        "${CMAKE_BINARY_DIR}/GsConfigHeader.h"
      COMMENT "Generating Config (Empty default)"
    )  
  ELSE ()
    ADD_CUSTOM_COMMAND(
      OUTPUT GsConfigHeader.h
      DEPENDS GsCommonConfigHeaderGen
              "${GITTEST_COMMON_CONFIG_GENERATION_FILEPATH}"
      COMMAND GsCommonConfigHeaderGen
        "${GITTEST_COMMON_CONFIG_GENERATION_FILEPATH}"
        "${CMAKE_BINARY_DIR}/GsConfigHeader.h"
      COMMENT "Generating Config"
    )  
  ENDIF ()
ENDFUNCTION ()

FUNCTION (GITTEST_COMMON_SET_LIB)

  SET(GITTEST_COMMON_HEADERS
    GsConfigHeader.h    # for Config Header Generator
    ${GITTEST_COMMON_PREFIX}/include/gittest/bypart.h
    ${GITTEST_COMMON_PREFIX}/include/gittest/cbuf.h
    ${GITTEST_COMMON_PREFIX}/include/gittest/config.h
    ${GITTEST_COMMON_PREFIX}/include/gittest/config_defs.h
    ${GITTEST_COMMON_PREFIX}/include/gittest/filesys.h
    ${GITTEST_COMMON_PREFIX}/include/gittest/log.h
    ${GITTEST_COMMON_PREFIX}/include/gittest/log_defs.h
    ${GITTEST_COMMON_PREFIX}/include/gittest/misc.h
  )
  
  SET(GITTEST_COMMON_SOURCES
    ${GITTEST_COMMON_PREFIX}/src/bypart.cpp
    ${GITTEST_COMMON_PREFIX}/src/cbuf.cpp
    ${GITTEST_COMMON_PREFIX}/src/config.cpp
    ${GITTEST_COMMON_PREFIX}/src/filesys.cpp
    ${GITTEST_COMMON_PREFIX}/src/log.cpp
    ${GITTEST_COMMON_PREFIX}/src/log_unified.cpp
    ${GITTEST_COMMON_PREFIX}/src/misc.cpp
  )
  
  SET(GITTEST_COMMON_HEADERS_NIX
    ${GITTEST_COMMON_PREFIX}/include/gittest/filesys_nix.h
  )
  SET(GITTEST_COMMON_HEADERS_WIN
    ${GITTEST_COMMON_PREFIX}/include/gittest/filesys_win.h
  )
  
  SET(GITTEST_COMMON_SOURCES_NIX
    ${GITTEST_COMMON_PREFIX}/src/filesys_nix.cpp
    ${GITTEST_COMMON_PREFIX}/src/log_nix.cpp
    ${GITTEST_COMMON_PREFIX}/src/misc_nix.cpp
  )
  SET(GITTEST_COMMON_SOURCES_WIN
    ${GITTEST_COMMON_PREFIX}/src/filesys_win.cpp
    ${GITTEST_COMMON_PREFIX}/src/log_win.cpp
    ${GITTEST_COMMON_PREFIX}/src/misc_win.cpp
  )
  
  IF (WIN32)
    SET(GITTEST_COMMON_SOURCES_PLATFORM_ALL
      ${GITTEST_COMMON_HEADERS}
      ${GITTEST_COMMON_SOURCES}
      ${GITTEST_COMMON_HEADERS_WIN}
      ${GITTEST_COMMON_SOURCES_WIN}
    )
  ELSEIF (UNIX)
    SET(GITTEST_COMMON_SOURCES_PLATFORM_ALL
      ${GITTEST_COMMON_HEADERS}
      ${GITTEST_COMMON_SOURCES}
      ${GITTEST_COMMON_HEADERS_NIX}
      ${GITTEST_COMMON_SOURCES_NIX}
    )
  ENDIF ()

  ADD_LIBRARY(gittest_common STATIC ${GITTEST_COMMON_SOURCES_PLATFORM_ALL})
  
  TARGET_INCLUDE_DIRECTORIES(gittest_common
    PUBLIC ${GITTEST_COMMON_PREFIX}/include
    # For Generated Header
    PUBLIC ${CMAKE_BINARY_DIR}
  )
    
  TARGET_COMPILE_DEFINITIONS(gittest_common PUBLIC
    # FIXME: WIN hardcoded
    -DEXTERNAL_GS_CONFIG_DEFS_GLOBAL_DEBUG_BREAK=GS_CONFIG_DEFS_WIN
    -DEXTERNAL_GS_CONFIG_DEFS_GLOBAL_CLEAN_HANDLING=GS_CONFIG_DEFS_NONE
  )

  IF (WIN32)
    FIND_PACKAGE(Shlwapi REQUIRED)
    TARGET_LINK_LIBRARIES(gittest_common
      ${SHLWAPI_LIBRARIES}
    )
  ELSEIF (UNIX)
    TARGET_LINK_LIBRARIES(gittest_common
    )
  ENDIF ()
  
ENDFUNCTION()
