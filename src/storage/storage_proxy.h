/*
    Procmon-for-Linux

    Copyright (c) Microsoft Corporation

    All rights reserved.

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

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