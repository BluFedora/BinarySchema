#
# BinarySchema
#

project(AssetIO_BinarySchema VERSION 0.0.1 DESCRIPTION "")

option(BINARY_SCHEMA_UNIT_TESTS "Enable unit testing target for BinarySchema." ON)

add_library(
  AssetIO_BinarySchema STATIC

    "include/binary_schema.hpp"

    "src/binary_schema.cpp"
)

target_include_directories(
  AssetIO_BinarySchema

  PUBLIC
    "${PROJECT_SOURCE_DIR}/include"
)

target_link_libraries(
  AssetIO_BinarySchema

  PUBLIC
    AssetIO_BinaryIO
    LibFoundation_Memory
)

set_property(TARGET AssetIO_BinarySchema PROPERTY FOLDER "BluFedora/AssetIO")

if (BINARY_SCHEMA_UNIT_TESTS)
  include(FetchContent)
  FetchContent_Declare(
    Catch2
    GIT_REPOSITORY https://github.com/catchorg/Catch2.git
    GIT_TAG        v3.7.0
  )
  FetchContent_MakeAvailable(Catch2)

  add_executable(
    BinarySchemaTest
      "test/binary_schema_test_main.cpp"
  )

  target_link_libraries(
    BinarySchemaTest

    PRIVATE
      AssetIO_BinarySchema
      Catch2::Catch2
      Catch2::Catch2WithMain
  )
  set_property(TARGET BinarySchemaTest PROPERTY FOLDER "BluFedora/Test")

  include(CTest)
  include(Catch)
  catch_discover_tests(BinarySchemaTest)
endif()
