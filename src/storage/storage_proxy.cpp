// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include "storage_proxy.h"

const std::map<std::string, StorageProxy::StorageEngineType> StorageProxy::storageEngineTypeMap = 
{
    { "mock", StorageProxy::StorageEngineType::Mock },
    { "sql", StorageProxy::StorageEngineType::Sql }
};