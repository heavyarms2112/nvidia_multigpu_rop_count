#define _GNU_SOURCE
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <dirent.h>
#include <errno.h>
#include <stdlib.h>

#define NV_ALIGN_BYTES(size) __attribute__ ((aligned (size)))
#define NV_DECLARE_ALIGNED(TYPE_VAR, ALIGN) TYPE_VAR __attribute__ ((aligned (ALIGN)))

typedef unsigned __INT32_TYPE__ NvV32;
typedef unsigned __INT32_TYPE__ NvU32;
typedef NvU32 NvHandle;
typedef void* NvP64;
typedef uint64_t NvU64;

#define NV_IOCTL_MAGIC      'F'
#define NV_IOCTL_BASE       200
#define NV_ESC_REGISTER_FD           (NV_IOCTL_BASE + 1)
#define NV_ESC_RM_CONTROL                           0x2A
#define NV_ESC_RM_ALLOC                             0x2B

#define NV01_DEVICE_0      (0x80U)
#define NV20_SUBDEVICE_0      (0x2080U)

#define CMD_SUBDEVICE_CTRL_GR_GET_ROP_INFO 0x20801213

typedef struct
{
    NvHandle hRoot;
    NvHandle hObjectParent;
    NvHandle hObjectNew;
    NvV32    hClass;
    NvP64    pAllocParms NV_ALIGN_BYTES(8);
    NvU32    paramsSize;
    NvV32    status;
} NVOS21_PARAMETERS;

typedef struct
{
    NvHandle hRoot;
    NvHandle hObjectParent;
    NvHandle hObjectNew;
    NvV32    hClass;
    NvP64    pAllocParms NV_ALIGN_BYTES(8);
    NvP64    pRightsRequested NV_ALIGN_BYTES(8);
    NvU32    paramsSize;
    NvU32    flags;
    NvV32    status;
} NVOS64_PARAMETERS;

typedef struct
{
    NvHandle hClient;
    NvHandle hObject;
    NvV32    cmd;
    NvU32    flags;
    NvP64    params NV_ALIGN_BYTES(8);
    NvU32    paramsSize;
    NvV32    status;
} NVOS54_PARAMETERS;

typedef struct
{
    NvU32 deviceId;
    NvHandle hClientShare;
    NvHandle hTargetClient;
    NvHandle hTargetDevice;
    NvV32 flags;
    NV_DECLARE_ALIGNED(NvU64 vaSpaceSize, 8);
    NV_DECLARE_ALIGNED(NvU64 vaStartInternal, 8);
    NV_DECLARE_ALIGNED(NvU64 vaLimitInternal, 8);
    NvV32 vaMode;
} NV0080_ALLOC_PARAMETERS;

typedef struct
{
    NvU32 subDeviceId;
} NV2080_ALLOC_PARAMETERS;

typedef struct
{
    NvU32 ropUnitCount;
    NvU32 ropOperationsFactor;
    NvU32 ropOperationsCount;
} NV2080_CTRL_GR_GET_ROP_INFO_PARAMS;

typedef struct {
    char pci_bus_id[256];  // increased from 32
    int minor;
    int gpu_index;
    char name[128];
} gpu_info_t;

#define MAX_GPUS 32

static int enumerate_gpus(gpu_info_t *gpus, int max_gpus) {
    DIR *dir = opendir("/proc/driver/nvidia/gpus");
    if (!dir) {
        perror("Failed to open /proc/driver/nvidia/gpus");
        return -1;
    }
    struct dirent *entry;
    int count = 0;

    while ((entry = readdir(dir)) != NULL && count < max_gpus) {
        if (entry->d_name[0] == '.') continue;

        snprintf(gpus[count].pci_bus_id, sizeof(gpus[count].pci_bus_id), "%s", entry->d_name);

        gpus[count].gpu_index = count;
        gpus[count].minor = count;

        char info_path[512];  // increased from 128
        snprintf(info_path, sizeof(info_path), "/proc/driver/nvidia/gpus/%s/information", entry->d_name);
        FILE *f = fopen(info_path, "r");
        if (f) {
            char line[256];
            while (fgets(line, sizeof(line), f)) {
                if (strncmp(line, "Model:", 6) == 0) {
                    char *model = line + 6;
                    while (*model == '\t' || *model == ' ') model++;
                    size_t len = strlen(model);
                    if (len > 0 && model[len-1] == '\n') model[len-1] = 0;
                    strncpy(gpus[count].name, model, sizeof(gpus[count].name)-1);
                    gpus[count].name[sizeof(gpus[count].name)-1] = 0;
                    break;
                }
            }
            fclose(f);
        } else {
            snprintf(gpus[count].name, sizeof(gpus[count].name), "Unknown GPU");
        }

        count++;
    }
    closedir(dir);
    return count;
}

static bool open_nvidiactl(int* const nvidiactl_fd) {
    *nvidiactl_fd = open("/dev/nvidiactl", O_RDWR);
    if (*nvidiactl_fd == -1)
        perror("open /dev/nvidiactl");
    return *nvidiactl_fd != -1;
}

static bool open_nvidiaX(int minor, int* const nvidiaX_fd) {
    char path[32];
    snprintf(path, sizeof(path), "/dev/nvidia%d", minor);
    *nvidiaX_fd = open(path, O_RDWR | O_CLOEXEC);
    if (*nvidiaX_fd == -1) {
        fprintf(stderr, "Failed to open %s: %s\n", path, strerror(errno));
        return false;
    }
    return true;
}

static bool alloc_client(const int nvidiactl_fd, NvHandle* const hClient) {
    NVOS21_PARAMETERS request;
    memset(&request, 0, sizeof(request));
    if (ioctl(nvidiactl_fd, _IOC(_IOC_READ|_IOC_WRITE, NV_IOCTL_MAGIC, NV_ESC_RM_ALLOC, sizeof(request)), &request) != 0) {
        perror("alloc_client ioctl");
        return false;
    }
    *hClient = request.hObjectNew;
    return request.status == 0;
}

static bool alloc_device(const int nvidiactl_fd, const NvHandle hClient, NvHandle* const hDevice, int device_id) {
    NV0080_ALLOC_PARAMETERS allocParams;
    memset(&allocParams, 0, sizeof(allocParams));
    allocParams.deviceId = device_id;

    NVOS64_PARAMETERS request;
    memset(&request, 0, sizeof(request));
    request.hRoot = hClient;
    request.hObjectParent = hClient;
    request.hObjectNew = 0;
    request.hClass = NV01_DEVICE_0;
    request.pAllocParms = &allocParams;
    request.pRightsRequested = NULL;
    request.paramsSize = sizeof(allocParams);
    request.flags = 0;
    request.status = 0;

    int ret = ioctl(nvidiactl_fd, _IOC(_IOC_READ|_IOC_WRITE, NV_IOCTL_MAGIC, NV_ESC_RM_ALLOC, sizeof(request)), &request);
    if (ret != 0)
        return false;
    if (request.status != 0)
        return false;
    *hDevice = request.hObjectNew;
    return true;
}

static bool alloc_subdevice(const int nvidiactl_fd, const NvHandle hClient, const NvHandle hParentDevice, NvHandle* const hSubDevice) {
    NV2080_ALLOC_PARAMETERS allocParams;
    memset(&allocParams, 0, sizeof(allocParams));

    NVOS64_PARAMETERS request;
    memset(&request, 0, sizeof(request));
    request.hRoot = hClient;
    request.hObjectParent = hParentDevice;
    request.hObjectNew = 0;
    request.hClass = NV20_SUBDEVICE_0;
    request.pAllocParms = &allocParams;
    request.pRightsRequested = NULL;
    request.paramsSize = sizeof(allocParams);
    request.flags = 0;
    request.status = 0;

    int ret = ioctl(nvidiactl_fd, _IOC(_IOC_READ|_IOC_WRITE, NV_IOCTL_MAGIC, NV_ESC_RM_ALLOC, sizeof(request)), &request);
    if (ret != 0)
        return false;
    if (request.status != 0)
        return false;
    *hSubDevice = request.hObjectNew;
    return true;
}

static bool get_rop_count(const int nvidiactl_fd, const NvHandle hClient, const NvHandle hSubdevice, NV2080_CTRL_GR_GET_ROP_INFO_PARAMS* ropParams) {
    NVOS54_PARAMETERS request;
    memset(&request, 0, sizeof(request));
    request.hClient = hClient;
    request.hObject = hSubdevice;
    request.cmd = CMD_SUBDEVICE_CTRL_GR_GET_ROP_INFO;
    request.flags = 0;
    request.params = ropParams;
    request.paramsSize = sizeof(NV2080_CTRL_GR_GET_ROP_INFO_PARAMS);
    request.status = 0;

    int ret = ioctl(nvidiactl_fd, _IOC(_IOC_READ|_IOC_WRITE, NV_IOCTL_MAGIC, NV_ESC_RM_CONTROL, sizeof(request)), &request);
    if (ret != 0)
        return false;
    if (request.status != 0)
        return false;
    return true;
}

int main(void) {
    gpu_info_t gpus[MAX_GPUS];
    int num_gpus = enumerate_gpus(gpus, MAX_GPUS);
    if (num_gpus <= 0) {
        fprintf(stderr, "No NVIDIA GPUs detected via /proc/driver/nvidia/gpus\n");
        return 1;
    }

    int nvidiactl_fd;
    if (!open_nvidiactl(&nvidiactl_fd)) {
        fprintf(stderr, "Failed to open /dev/nvidiactl\n");
        return 1;
    }

    printf("%-5s %-30s %12s %8s %10s\n",
        "GPU#", "GPU Name", "ROP Units", "Factor", "Count");
    printf("----------------------------------------------------------------------------\n");

    for (int i = 0; i < num_gpus; ++i) {
        gpu_info_t *gpu = &gpus[i];

        int nvidiaX_fd;
        if (!open_nvidiaX(gpu->minor, &nvidiaX_fd)) {
            fprintf(stderr, "%-5d %-30s %12s %8s %10s\n",
                gpu->gpu_index, gpu->name, "Open Failed", "-", "-");
            continue;
        }

        NvHandle hClient;
        if (!alloc_client(nvidiactl_fd, &hClient)) {
            fprintf(stderr, "%-5d %-30s %12s %8s %10s\n",
                gpu->gpu_index, gpu->name, "Client Fail", "-", "-");
            close(nvidiaX_fd);
            continue;
        }

        NvHandle hDevice;
        if (!alloc_device(nvidiactl_fd, hClient, &hDevice, gpu->gpu_index)) {
            fprintf(stderr, "%-5d %-30s %12s %8s %10s\n",
                gpu->gpu_index, gpu->name, "Device Fail", "-", "-");
            close(nvidiaX_fd);
            continue;
        }

        NvHandle hSubDevice;
        if (!alloc_subdevice(nvidiactl_fd, hClient, hDevice, &hSubDevice)) {
            fprintf(stderr, "%-5d %-30s %12s %8s %10s\n",
                gpu->gpu_index, gpu->name, "Subdev Fail", "-", "-");
            close(nvidiaX_fd);
            continue;
        }

        NV2080_CTRL_GR_GET_ROP_INFO_PARAMS ropParams;
        memset(&ropParams, 0, sizeof(ropParams));
        if (!get_rop_count(nvidiactl_fd, hClient, hSubDevice, &ropParams)) {
            fprintf(stderr, "%-5d %-30s %12s %8s %10s\n",
                gpu->gpu_index, gpu->name, "ROP Fail", "-", "-");
            close(nvidiaX_fd);
            continue;
        }

        printf("%-5d %-30s %12u %8u %10u\n",
            gpu->gpu_index, gpu->name,
            ropParams.ropUnitCount,
            ropParams.ropOperationsFactor,
            ropParams.ropOperationsCount);

        close(nvidiaX_fd);
    }

    close(nvidiactl_fd);
    return 0;
}

