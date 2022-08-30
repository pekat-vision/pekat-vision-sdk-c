/**
 * @brief 
 * PEKAT VISION api
 * 
 * A C/C++ library for communication with PEKAT VISION 3.10.2 and higher
 * 
 * Author: developers@pekatvision.com
 * Date:   30 August 2022
 * Web:    https://github.com/pekat-vision
 */


#ifndef PEKAT_VISION_SDK
#define PEKAT_VISION_SDK

#ifdef _WIN32
#ifdef PEKATVISIONSDK_EXPORTS
#define PEKAT_VISION_SDK_API __declspec(dllexport)
#else
#define PEKAT_VISION_SDK_API __declspec(dllimport)
#endif
#else
#define PEKAT_VISION_SDK_API
#endif

#ifdef  __cplusplus
extern "C" {
#endif

typedef struct _pv_analyzer pv_analyzer;

typedef enum {
    PVRT_CONTEXT,
    PVRT_ANNOTATED_IMAGE,
    PVRT_HEATMAP
} pv_result_type;

#define PVR_OK 0
#define PVR_NOMEM -1
#define PVR_CURL -2
#define PVR_CURLU -3
#define PVR_WINHTTP -4
#define PVR_WRONG_MBS -5

/**
 * Create new analyzer by running the server in background. Pass path to server and project, optionally API key and other parameters.
 * All strings are no longer used after call so you are free to modify/remove them. Returns created analyzer or NULL on error.
 */
PEKAT_VISION_SDK_API pv_analyzer *pv_create_local_analyzer(const char *dist_path, const char *project_path, const char *api_key, char *const argv[]);
/**
 * Create new analyzer using already running server. All strings are no longer used after call. Returns analyzer or NULL on error.
 */
PEKAT_VISION_SDK_API pv_analyzer *pv_create_remote_analyzer(const char *host, int port, const char *api_key);
/**
 * Clone existing analyzer, i.e. creates a new client from existing one. Note that multiple clones of local analyzer will share
 * the same running background server but only the one created via create_local_analyzer() keeps it alive. After closing that
 * analyzer, all the others will lose the server and stop working.
 */
PEKAT_VISION_SDK_API pv_analyzer *pv_clone_analyzer(pv_analyzer *orig);

/**
 * Set whether context should be sent in request body. Context is sent in body by default.
 */
PEKAT_VISION_SDK_API void pv_set_context_in_body(pv_analyzer *, unsigned char context_in_body);


/**
 * Analyze image. Passed data are used only during the call. Returns zero on success, one of PVR_xxx error codes (negative),
 * or HTTP status code (positive) on error. On success, use on of pv_get_result_xxx() functions to obtain result data. Note
 * that next call to this function will invalidate the result so you need to make a copy before next call.
 */
PEKAT_VISION_SDK_API int pv_analyze_image(pv_analyzer *, const char *image, int len, pv_result_type result_type, const char *data, double timeout);

/**
 * Analyze raw image. Passed data are used only during the call. Returns zero on success, one of PVR_xxx error codes (negative),
 * or HTTP status code (positive) on error. On success, use on of pv_get_result_xxx() functions to obtain result data. Note
 * that next call to this function will invalidate the result so you need to make a copy before next call.
 */
PEKAT_VISION_SDK_API int pv_analyze_raw_image(pv_analyzer *, const char *image, int width, int height, pv_result_type result_type, const char *data, double timeout);

/**
 * Get result image data. Returned pointer is valid until next call of pv_analyze_image() or destruction of analyzer.
 * Returns NULL if no data were returned (only context).
 */
PEKAT_VISION_SDK_API char *pv_get_result_data(pv_analyzer *analyzer);
/**
 * Returns length of image data.
 */
PEKAT_VISION_SDK_API int pv_get_result_data_size(pv_analyzer *analyzer);
/**
 * Get result context or NULL if none. Returned string is zero-terminated and valid until next call of pv_analyze_image() or
 * destruction of analyzer.
 */
PEKAT_VISION_SDK_API char *pv_get_result_context(pv_analyzer *analyzer);

/**
 * Destroy analyzer. In case of local one, this call will stop the background server.
 */
PEKAT_VISION_SDK_API void pv_free_analyzer(pv_analyzer *);

#ifdef LIBCURL_VERSION
/* include these only when user has curl - avoid curl headers when error codes are not needed */

/**
 * Get CURL error from last call. Call to get details when status is PVR_CURL.
 */
PEKAT_VISION_SDK_API CURLcode pv_get_curl_code(pv_analyzer *);
/**
 * Get CURL URL error from last call. Call to get details when status is PVR_CURLU.
 */
PEKAT_VISION_SDK_API CURLUcode pv_get_curlu_code(pv_analyzer *);
#endif

#ifdef  __cplusplus
}
#endif

#endif
