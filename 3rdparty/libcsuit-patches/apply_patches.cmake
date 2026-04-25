# apply_patches.cmake — invoked by ExternalProject_Add(... PATCH_COMMAND ...).
# Applies every .patch file in ${LIBCSUIT_PATCHES} to ${LIBCSUIT_DIR} idempotently.
#
# Inputs (set with -D when invoking via ${CMAKE_COMMAND} -P):
#   LIBCSUIT_DIR     — source tree to patch
#   LIBCSUIT_PATCHES — directory containing *.patch files

if(NOT LIBCSUIT_DIR OR NOT LIBCSUIT_PATCHES)
    message(FATAL_ERROR "LIBCSUIT_DIR and LIBCSUIT_PATCHES must be set")
endif()

file(GLOB _patch_files "${LIBCSUIT_PATCHES}/*.patch")
list(SORT _patch_files)

foreach(_patch ${_patch_files})
    # If the patch is already applied, `git apply --reverse --check` succeeds
    # and we skip it. Otherwise apply it; failure is fatal.
    execute_process(
        COMMAND git -C "${LIBCSUIT_DIR}" apply --reverse --check "${_patch}"
        RESULT_VARIABLE _already_applied
        OUTPUT_QUIET
        ERROR_QUIET)

    if(_already_applied EQUAL 0)
        message(STATUS "libcsuit patch already applied: ${_patch}")
    else()
        message(STATUS "Applying libcsuit patch: ${_patch}")
        execute_process(
            COMMAND git -C "${LIBCSUIT_DIR}" apply "${_patch}"
            RESULT_VARIABLE _rc)
        if(NOT _rc EQUAL 0)
            message(FATAL_ERROR "Failed to apply ${_patch} (rc=${_rc})")
        endif()
    endif()
endforeach()
