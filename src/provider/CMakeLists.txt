# Windows only (included from the top level when ATLAS_BUILD_PROVIDER is ON).
add_library(atlas_win STATIC winutil.cpp winkey.cpp dpapi_store.cpp winhttp_client.cpp agent.cpp webauthn_win.cpp cli_pipe.cpp sso_common.cpp)
target_include_directories(atlas_win PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(atlas_win PUBLIC atlas_core ncrypt crypt32 winhttp advapi32 shlwapi ole32 uuid bcrypt)
target_compile_definitions(atlas_win PUBLIC UNICODE _UNICODE WIN32_LEAN_AND_MEAN NOMINMAX)
target_compile_options(atlas_win PUBLIC /W4 /utf-8)

add_library(atlas_credential_provider SHARED provider.cpp register.cpp provider.def)
target_link_libraries(atlas_credential_provider PRIVATE atlas_win)

add_executable(atlas-enroll enroll_main.cpp)
target_link_libraries(atlas-enroll PRIVATE atlas_win)

add_executable(atlas-passkey passkey_main.cpp)
target_link_libraries(atlas-passkey PRIVATE atlas_win)

add_executable(atlas-sync sync_main.cpp)
target_link_libraries(atlas-sync PRIVATE atlas_win)

add_executable(atlas-cli-mfa cli_mfa_main.cpp)
target_link_libraries(atlas-cli-mfa PRIVATE atlas_win)

add_executable(atlas-sso-broker sso_broker_main.cpp)
target_link_libraries(atlas-sso-broker PRIVATE atlas_win)

add_executable(atlas-sso-native-host sso_native_host.cpp)
target_link_libraries(atlas-sso-native-host PRIVATE atlas_win)

install(TARGETS atlas_credential_provider atlas-enroll atlas-passkey atlas-sync atlas-cli-mfa atlas-sso-broker atlas-sso-native-host RUNTIME DESTINATION bin)
