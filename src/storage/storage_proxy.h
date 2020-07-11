// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include <algorithm>
#include <string>
#include <vector>

#include "storage_engine.h"
#include "mock_storage_engine.h"
#include "sqlite3_storage_engine.h"

class StorageProxy
{
  public:
    // Add new storage types here
    enum StorageEngineType
    {
        Mock,
        Sql
    };

    static const std::map<std::string, StorageEngineType> storageEngineTypeMap;

    static bool IsValidStorageEngineType(std::string type)
    {
        std::transform(type.begin(), type.end(), type.begin(), [](unsigned char c) { return std::tolower(c); });
        auto foundType = storageEngineTypeMap.find(type);
        return foundType != storageEngineTypeMap.end();
    };

    static IStorageEngine *StorageFactory(StorageEngineType type)
    {
        switch (type)
        {
        case StorageEngineType::Mock:
            return new MockStorageEngine();

        case StorageEngineType::Sql:
            return new Sqlite3StorageEngine();
        default:
            // TODO: handle this error better...
            return new MockStorageEngine();
        }
    };

    static IStorageEngine *StorageFactory(std::string type)
    {
        StorageEngineType foundType = GetStorageTypeForString(type);
        return StorageFactory(foundType);
    };

    static StorageEngineType GetStorageTypeForString(std::string type)
    {
        std::transform(type.begin(), type.end(), type.begin(), [](unsigned char c) { return std::tolower(c); });
        auto foundType = storageEngineTypeMap.find(type);
        if (foundType == storageEngineTypeMap.end()) return StorageEngineType::Mock;

        return foundType->second;
    };
};