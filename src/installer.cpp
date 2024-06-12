#include <iostream>
#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>

#include "installer.h"

extern "C"
{
    #include "libsysinternalsEBPF.h"
}

mode_t fileMode = S_IRUSR | S_IWUSR;

extern char _binary_procmonEBPFkern4_17_5_1_o_start[];
extern char _binary_procmonEBPFkern4_17_5_1_o_end[];
extern char _binary_procmonEBPFkern5_2_o_start[];
extern char _binary_procmonEBPFkern5_2_o_end[];
extern char _binary_procmonEBPFkern5_3_5_5_o_start[];
extern char _binary_procmonEBPFkern5_3_5_5_o_end[];
extern char _binary_procmonEBPFkern5_6__o_start[];
extern char _binary_procmonEBPFkern5_6__o_end[];
extern char _binary_procmonEBPFkern4_17_5_1_core_o_start[];
extern char _binary_procmonEBPFkern4_17_5_1_core_o_end[];
extern char _binary_procmonEBPFkern5_2_core_o_start[];
extern char _binary_procmonEBPFkern5_2_core_o_end[];
extern char _binary_procmonEBPFkern5_3_5_5_core_o_start[];
extern char _binary_procmonEBPFkern5_3_5_5_core_o_end[];
extern char _binary_procmonEBPFkern5_6__core_o_start[];
extern char _binary_procmonEBPFkern5_6__core_o_end[];

//--------------------------------------------------------------------
//
// ExtractEBPFPrograms
//
// Extracts the EBPF programs from the procmon binary and places them
// in /tmp
//
//--------------------------------------------------------------------
bool ExtractEBPFPrograms()
{
    if (!dropFile(PROCMON_EBPF_INSTALL_DIR "/" KERN_4_17_5_1_OBJ,
        _binary_procmonEBPFkern4_17_5_1_o_start,
        _binary_procmonEBPFkern4_17_5_1_o_end,
        true,
        fileMode))
        {
            return false;
        }

    if (!dropFile(PROCMON_EBPF_INSTALL_DIR "/" KERN_5_2_OBJ,
        _binary_procmonEBPFkern5_2_o_start,
        _binary_procmonEBPFkern5_2_o_end,
        true,
        fileMode))
        {
            return false;
        }

    if (!dropFile(PROCMON_EBPF_INSTALL_DIR "/" KERN_5_3_5_5_OBJ,
        _binary_procmonEBPFkern5_3_5_5_o_start,
        _binary_procmonEBPFkern5_3_5_5_o_end,
        true,
        fileMode))
        {
            return false;
        }

    if (!dropFile(PROCMON_EBPF_INSTALL_DIR "/" KERN_5_6__OBJ,
        _binary_procmonEBPFkern5_6__o_start,
        _binary_procmonEBPFkern5_6__o_end,
        true,
        fileMode))
        {
            return false;
        }

    if (!dropFile(PROCMON_EBPF_INSTALL_DIR "/" KERN_4_17_5_1_CORE_OBJ,
        _binary_procmonEBPFkern4_17_5_1_core_o_start,
        _binary_procmonEBPFkern4_17_5_1_core_o_end,
        true,
        fileMode))
        {
            return false;
        }

    if (!dropFile(PROCMON_EBPF_INSTALL_DIR "/" KERN_5_2_CORE_OBJ,
        _binary_procmonEBPFkern5_2_core_o_start,
        _binary_procmonEBPFkern5_2_core_o_end,
        true,
        fileMode))
        {
            return false;
        }

    if (!dropFile(PROCMON_EBPF_INSTALL_DIR "/" KERN_5_3_5_5_CORE_OBJ,
        _binary_procmonEBPFkern5_3_5_5_core_o_start,
        _binary_procmonEBPFkern5_3_5_5_core_o_end,
        true,
        fileMode))
        {
            return false;
        }

    if (!dropFile(PROCMON_EBPF_INSTALL_DIR "/" KERN_5_6__CORE_OBJ,
        _binary_procmonEBPFkern5_6__core_o_start,
        _binary_procmonEBPFkern5_6__core_o_end,
        true,
        fileMode))
        {
            return false;
        }

    return true;
}

//--------------------------------------------------------------------
//
// DeleteEBPFPrograms
//
// Deletes the temporary eBPF programs from /tmp
//
//--------------------------------------------------------------------
bool DeleteEBPFPrograms()
{
    DIR* dir = opendir(PROCMON_EBPF_INSTALL_DIR);
    if (dir == nullptr)
    {
        return false;
    }

    struct dirent* entry;
    while ((entry = readdir(dir)) != nullptr)
    {
        std::string filename(entry->d_name);
        if (filename.find("procmon") == 0)
        {
            std::string filepath = PROCMON_EBPF_INSTALL_DIR "/" + filename;
            struct stat fileStat;
            if (stat(filepath.c_str(), &fileStat) == 0 && S_ISREG(fileStat.st_mode))
            {
                unlink(filepath.c_str());
            }
        }
    }

    closedir(dir);

    return true;
}