project(signature_scanner)
add_library(signature_scanner STATIC src/SignatureScanner.cpp)
target_include_directories(signature_scanner PUBLIC include)
add_subdirectory(src)