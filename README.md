# PEKAT VISION SDK

A simple ANSI C library for communication with PEKAT VISION for Linux and Windows.

## Requirements

* On Linux libCURL at least 7.62.0
* PEKAT VISION 3.10.2 or higher

## Installation

The interface (header file) is the same for both platforms but the implementation is completely different. Because of this, there are two source
files, one for each platform.

### Linux (sdk_linux.c)

Just compile the sources either as part of your sources or create an external library. You can use your favorite build tool like CMake or Autoconf or
just use `curl-config` to get correct options for compilation with CURL.

For example:

```
gcc `curl-config --cflags` pekatvision/sdk_linux.c test.c -o test `curl-config --libs`
```

### Windows (sdk_windows.c)

There is a Visual Studio project for Windows which can be used to build DLL. Or you can put the sources into you own project just like with Linux. In
both cases you will have to add `winhttp.lib` into additional dependencies for you application (project properties -> Linker -> Additional
Dependencies).

## Usage

Create local analyzer (will start Pekat Vision server in background):

```c
#include "pekatvision/sdk.h"

pv_analyzer *analyzer = pv_create_local_analyzer("/path/to/server/installation", "/path/to/project", "optional api key", NULL);
if (analyzer == NULL) {
    /* failed */
}
```

Run analysis:

```c
char *image;
int image_size;

int res = pv_analyze_image(analyzer, image, image_size, PVRT_HEATMAP, NULL);
if (res) {
    /* failed */
} else {
    char *res_image = pv_get_result_data(analyzer)
    int *res_size = pv_get_result_data_size(analyzer)
    char *res_context = pv_get_result_context(analyzer);
}
```

You pass buffer with PNG image inside and its length. The image is used only during invocation and is not modified. You can remove it after the call.
The last parameter is for additional data (string).

Returned values are kept inside analyzer and will be invalidated by next call to `pv_analyze_image()`.

At the end you have to remove the analyzer. This will also destroy the server.

```c
pv_free_analyzer(analyzer);
```

You can also connect to already running server using:

```c
pv_analyzer *analyzer = pv_create_remote_analyzer("host", 1234 /* port */, "optional api key");
```

Analyzer is not thread safe (you cannot run two analyses simultaneously). To overcome this issue, you can create clone of existing analyzer:

```c
pv_analyzer *analyzer = pv_clone_analyzer(orig);
```

Note however, that you will need to set up CURL for threading manually before using this SDK.

### Multiple cameras

```c
/* create local analyzer */
pv_analyzer *analyzer_camera_1 = pv_create_local_analyzer("/pekat_vision", "/home/peter/PekatVisionProjects/camera_1", "", NULL);
pv_analyzer *analyzer_camera_2 = pv_create_local_analyzer("/pekat_vision", "/home/peter/PekatVisionProjects/camera_2", "", NULL);
pv_analyzer *analyzer_camera_3 = pv_create_local_analyzer("/pekat_vision", "/home/peter/PekatVisionProjects/camera_3", "", NULL);

/* analyze - loop */
pv_analyze_image(analyzer_camera_1, buffer, len, PVRT_CONTEXT, NULL);
char *res_context_camera_1 = pv_get_result_context(analyzer_camera_1);
pv_analyze_image(analyzer_camera_2, buffer, len, PVRT_CONTEXT, NULL);
char *res_context_camera_2 = pv_get_result_context(analyzer_camera_2);
pv_analyze_image(analyzer_camera_3, buffer, len, PVRT_CONTEXT, NULL);
char *res_context_camera_3 = pv_get_result_context(analyzer_camera_3);
```
