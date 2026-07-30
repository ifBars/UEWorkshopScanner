cmake_minimum_required(VERSION 3.24)

project(UEWorkshopScannerNative LANGUAGES CXX)

add_library(UEWorkshopScannerNative SHARED src/main.cpp)
target_compile_features(UEWorkshopScannerNative PRIVATE cxx_std_20)
target_compile_definitions(
    UEWorkshopScannerNative
    PRIVATE
        NOMINMAX
        WIN32_LEAN_AND_MEAN
)
target_link_libraries(UEWorkshopScannerNative PRIVATE bcrypt)

set_target_properties(
    UEWorkshopScannerNative
    PROPERTIES
        OUTPUT_NAME main
        PREFIX ""
)

